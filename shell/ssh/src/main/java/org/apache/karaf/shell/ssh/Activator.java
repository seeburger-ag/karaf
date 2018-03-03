/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.karaf.shell.ssh;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;

import org.apache.karaf.shell.api.action.lifecycle.Manager;
import org.apache.karaf.shell.api.console.CommandLoggingFilter;
import org.apache.karaf.shell.api.console.Session;
import org.apache.karaf.shell.api.console.SessionFactory;
import org.apache.karaf.shell.support.RegexCommandLoggingFilter;
import org.apache.karaf.util.tracker.BaseActivator;
import org.apache.karaf.util.tracker.annotation.Managed;
import org.apache.karaf.util.tracker.annotation.RequireService;
import org.apache.karaf.util.tracker.annotation.Services;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.config.keys.PublicKeyEntry;
import org.apache.sshd.common.file.virtualfs.VirtualFileSystemFactory;
import org.apache.sshd.common.util.security.bouncycastle.BouncyCastleGeneratorHostKeyProvider;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.auth.password.PasswordAuthenticator;
import org.apache.sshd.server.auth.password.PasswordChangeRequiredException;
import org.apache.sshd.server.auth.pubkey.PublickeyAuthenticator;
import org.apache.sshd.server.forward.AcceptAllForwardingFilter;
import org.apache.sshd.server.keyprovider.AbstractGeneratorHostKeyProvider;
import org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider;
import org.apache.sshd.server.scp.ScpCommandFactory;
import org.apache.sshd.server.session.ServerSession;
import org.apache.sshd.server.subsystem.sftp.SftpSubsystemFactory;
import org.osgi.framework.ServiceReference;
import org.osgi.service.cm.ManagedService;
import org.osgi.util.tracker.ServiceTracker;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.seeburger.security.wallet.PasswordProtector;

/**
 * Activate this bundle
 */
@Services(
        requires = @RequireService(SessionFactory.class)
)
@Managed("org.apache.karaf.shell")
public class Activator extends BaseActivator implements ManagedService {

    private static final String WELCOME_BANNER = "welcomeBanner";

    private static final String HOST_KEY_FORMAT = "hostKeyFormat";

    private static final String ALGORITHM2 = "algorithm";

    private static final String KEY_SIZE = "keySize";

    private static final String SSH_HOST = "ssh.bind.host";

    private static final String SSH_PORT = "ssh.port";

    private static final String SFTP_ENABLED = "sftpEnabled";

    private static final String KEX_ALGORITHMS = "kexAlgorithms";

    private static final String CIPHERS2 = "ciphers";

    private static final String MACS2 = "macs";

    private static final String AUTH_METHODS = "authMethods";

    private static final String SSH_IDLE_TIMEOUT = "sshIdleTimeout";



    static final Logger LOGGER = LoggerFactory.getLogger(Activator.class);

    ServiceTracker<Session, Session> sessionTracker;
    SessionFactory sessionFactory;
    SshServer server;
    private AbstractGeneratorHostKeyProvider keyProvider;

    private Properties settings;

    private File userConfFile;

    private void initializeConfig() throws FileNotFoundException, IOException
    {
        File confDir = new File(System.getProperty("bisas.conf","conf"),"keys/ssh");
        if(!confDir.exists())
            confDir.mkdirs();
        userConfFile = new File(confDir,"users.properties");
        settings = new Properties();
        File settingsFile = new File(confDir,"ssh.properties");
        if(settingsFile.isFile())
            load(settings,settingsFile);
        File portsPropertiesFile = new File(System.getProperty("bisas.software","software"),"ports.properties");

        Properties portsProperties = new Properties();
        if(portsPropertiesFile.isFile())
        {
            load(portsProperties,portsPropertiesFile);
        }
        int portOffset = Integer.parseInt(portsProperties.getProperty("port.offset", "0"));
        int sshPort = Integer.parseInt(portsProperties.getProperty("ssh.port", "8101"));
        String bindHost = portsProperties.getProperty("ssh.bind.host", "localhost");
        sshPort += portOffset;
        settings.put(SSH_PORT, String.valueOf(sshPort));
        settings.put(SSH_HOST, bindHost);

        File hostKeyFile = new File(confDir,"host.key");

        String hostKeyFormat  = getString(HOST_KEY_FORMAT, "PEM");
        if ("simple".equalsIgnoreCase(hostKeyFormat)) {
            keyProvider = new SimpleGeneratorHostKeyProvider();
        } else if ("PEM".equalsIgnoreCase(hostKeyFormat)) {
            keyProvider = new BouncyCastleGeneratorHostKeyProvider(hostKeyFile.toPath());
        } else {
            LOGGER.error("Invalid host key format " + hostKeyFormat);
            return;
        }

        if(hostKeyFile.exists())
        {
            // do not trash key file if there's something wrong with it.
            keyProvider.setOverwriteAllowed(false);
        }
        keyProvider.setKeySize(Integer.parseInt(settings.getProperty(KEY_SIZE, "4096")));
        keyProvider.setAlgorithm((String)settings.getOrDefault(ALGORITHM2, "RSA"));
        List<KeyPair> keys = keyProvider.loadKeys();
        if(!keys.isEmpty())
        {
            Properties userConf = new Properties();
            if(userConfFile.exists())
            {
                load(userConf,userConfFile);
            }
            KeyPair keyPair = keys.get(0);
            String encoded = PublicKeyEntry.toString(keyPair.getPublic());
            if(!encoded.equals(userConf.getProperty("admin.public.key")))
            {
                //store the current public key if it isn't correct or missing
                userConf.put("admin.public.key", encoded);
                userConf.put("admin", ""); //an empty password so it is disabled by default
                try(FileOutputStream out = new FileOutputStream(userConfFile))
                {
                    userConf.store(out, null);
                }
            }
        }
    }

    private void load(Properties props, File file) throws IOException
    {
        try(InputStream in = new FileInputStream(file))
        {
            props.load(in);
        }
    }

    @Override
    protected void doOpen() throws Exception {
        super.doOpen();

        sessionTracker = new ServiceTracker<Session, Session>(bundleContext, Session.class, null) {
            @Override
            public Session addingService(ServiceReference<Session> reference) {
                Session session = super.addingService(reference);
                KarafAgentFactory.getInstance().registerSession(session);
                return session;
            }
            @Override
            public void removedService(ServiceReference<Session> reference, Session session) {
                KarafAgentFactory.getInstance().unregisterSession(session);
                super.removedService(reference, session);
            }
        };
        sessionTracker.open();
    }

    @Override
    protected void doClose() {
        sessionTracker.close();
        super.doClose();
    }

    @Override
    protected void doStart() throws Exception {
        try
        {
            initializeConfig();
        }
        catch (Exception e)
        {
            LOGGER.error("Exception caught while creating SSH server configuration", e);
            return;
        }
        SessionFactory sf = getTrackedService(SessionFactory.class);
        if (sf == null) {
            return;
        }

        RegexCommandLoggingFilter filter = new RegexCommandLoggingFilter();
        filter.setPattern("ssh (.*?)-P +([^ ]+)");
        filter.setGroup(2);
        register(CommandLoggingFilter.class, filter);

        filter = new RegexCommandLoggingFilter();
        filter.setPattern("ssh (.*?)--password +([^ ]+)");
        filter.setGroup(2);
        register(CommandLoggingFilter.class, filter);

        sessionFactory = sf;
        sessionFactory.getRegistry().getService(Manager.class).register(SshAction.class);
        server = createSshServer(sessionFactory);
        this.bundleContext.registerService(SshServer.class, server, null);
        if (server == null) {
            return; // can result from bad specification.
        }
        try {
            server.start();
        } catch (IOException e) {
            LOGGER.warn("Exception caught while starting SSH server", e);
        }
    }

    @Override
    protected void doStop() {
        if (sessionFactory != null) {
            sessionFactory.getRegistry().getService(Manager.class).unregister(SshAction.class);
            sessionFactory = null;
        }
        if (server != null) {
            try {
                server.stop(true);
            } catch (IOException e) {
                LOGGER.warn("Exception caught while stopping SSH server", e);
            }
            server = null;
        }
        super.doStop();
    }

    protected SshServer createSshServer(SessionFactory sessionFactory) {
        int sshPort           = Integer.parseInt(settings.getProperty(SSH_PORT));
        String sshHost        = settings.getProperty(SSH_HOST);
        long sshIdleTimeout   = Long.parseLong(settings.getProperty(SSH_IDLE_TIMEOUT, "1800000"));
//        String sshRealm       = settings.getProperty("sshRealm", "karaf");
//        String sshRole        = settings.getProperty("sshRole", null);
//        String hostKey        = getString("hostKey", System.getProperty("bisas.conf") + "/keys/host.key");
//        String hostKeyFormat  = getString(HOST_KEY_FORMAT, "PEM");
        String authMethods    = settings.getProperty(AUTH_METHODS, "keyboard-interactive,password,publickey");
//        int keySize           = getInt(KEY_SIZE, 4096);
//        String algorithm      = getString(ALGORITHM2, "RSA");
        String macs           = settings.getProperty(MACS2, "hmac-sha2-512,hmac-sha2-256,hmac-sha1");
        String ciphers        = settings.getProperty(CIPHERS2, "aes128-ctr,arcfour128,aes128-cbc,3des-cbc,blowfish-cbc");
        String kexAlgorithms  = settings.getProperty(KEX_ALGORITHMS, "diffie-hellman-group-exchange-sha256,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha1,diffie-hellman-group1-sha1");
        String welcomeBanner  = settings.getProperty(WELCOME_BANNER, null);
        String moduliUrl      = settings.getProperty("moduli-url", null);
        boolean sftpEnabled   = Boolean.valueOf(settings.getProperty(SFTP_ENABLED, "false"));

        UserAuthFactoriesFactory authFactoriesFactory = new UserAuthFactoriesFactory();
        authFactoriesFactory.setAuthMethods(authMethods);

        SshServer server = SshServer.setUpDefaultServer();
        server.setPort(sshPort);
        server.setHost(sshHost);
        server.setMacFactories(SshUtils.buildMacs(macs));
        server.setCipherFactories(SshUtils.buildCiphers(ciphers));
        server.setKeyExchangeFactories(SshUtils.buildKexAlgorithms(kexAlgorithms));
        server.setShellFactory(new ShellFactoryImpl(sessionFactory));
        if (sftpEnabled) {
            server.setCommandFactory(new ScpCommandFactory.Builder().withDelegate(new ShellCommandFactory(sessionFactory)).build());
            server.setSubsystemFactories(Arrays.<NamedFactory<org.apache.sshd.server.Command>>asList(new SftpSubsystemFactory()));
            server.setFileSystemFactory(new VirtualFileSystemFactory(Paths.get(System.getProperty("bisas.data"))));
        } else {
            server.setCommandFactory(cmd -> new ShellCommand(sessionFactory, cmd));
        }
        server.setKeyPairProvider(keyProvider);
        server.setPasswordAuthenticator(new PasswordAuthenticator() {
            @Override
            public boolean authenticate(String username, String password, ServerSession session) throws PasswordChangeRequiredException {
                if(password==null || password.isEmpty())
                    return false;
                Properties userProps = new Properties();
                try
                {
                    load(userProps, userConfFile);
                    String decoded = new String(PasswordProtector.strip(userProps.getProperty(username,"").toCharArray()));
                    return password.equals(decoded);
                }
                catch(Exception e)
                {
                    LOGGER.error("Failed to parse users.properties",e);
                }
                return false;
            }
        });
        server.setPublickeyAuthenticator(new PublickeyAuthenticator()
        {
            @Override
            public boolean authenticate(String username, PublicKey key, ServerSession session)
            {
                Properties userProps = new Properties();
                try
                {
                    load(userProps, userConfFile);
                    if(userProps.containsKey(username+".public.key"))
                    {
                        String given = PublicKeyEntry.toString(key);
                        String expected = userProps.getProperty(username+".public.key");
                        return given.equals(expected);
                    }
                }
                catch (IOException e)
                {
                    LOGGER.error("Failed to parse users.properties",e);
                }
                return false;
            }
        });
        server.setUserAuthFactories(authFactoriesFactory.getFactories());
        server.setAgentFactory(KarafAgentFactory.getInstance());
        server.setTcpipForwardingFilter(AcceptAllForwardingFilter.INSTANCE);
        server.getProperties().put(SshServer.IDLE_TIMEOUT, Long.toString(sshIdleTimeout));
        if (moduliUrl != null) {
            server.getProperties().put(SshServer.MODULI_URL, moduliUrl);
        }
        if (welcomeBanner != null) {
            server.getProperties().put(SshServer.WELCOME_BANNER, welcomeBanner);
        }
        return server;
    }

}
