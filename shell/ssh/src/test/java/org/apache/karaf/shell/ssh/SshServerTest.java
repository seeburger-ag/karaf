/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.karaf.shell.ssh;

import org.apache.sshd.common.file.virtualfs.VirtualFileSystemFactory;
import org.apache.sshd.common.keyprovider.FileKeyPairProvider;
import org.apache.sshd.core.CoreModuleProperties;
import org.apache.sshd.scp.server.ScpCommandFactory;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.auth.password.AcceptAllPasswordAuthenticator;
import org.apache.sshd.server.auth.pubkey.AcceptAllPublickeyAuthenticator;
import org.apache.sshd.server.forward.AcceptAllForwardingFilter;
import org.apache.sshd.server.shell.ProcessShellCommandFactory;
import org.apache.sshd.server.shell.ProcessShellFactory;
import org.apache.sshd.sftp.server.SftpSubsystemFactory;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.nio.file.Paths;
import java.time.Duration;
import java.util.Collections;

/**
 * Example call:
 * plink.exe -batch -l admin -P 8122 -noagent -pwfile "C:\dev\test\nbr-as\etc\keys\pwd.txt" -v localhost "echo 'hello'";
 */
public class SshServerTest {

    private static SshServer server;


    @BeforeClass
    public static void init() throws IOException {
        server = createSshServer();
        server.start();
    }

    @AfterClass
    public static void destroy() throws IOException {
        server.stop();
    }

    @Test
    public void test() throws IOException {
        assertNotNull(server);
        assertTrue(server.isStarted());
        System.out.println("Started: " + server.getVersion() + " listening on " + server.getHost() + ':' + server.getPort());
        System.in.read(); // to keep server running until manually stopped
    }


    protected static SshServer createSshServer() {
        int sshPort                 = 8122;
        String sshHost              = "127.0.0.1";
        long sshIdleTimeout         = 1800000;
        int nioWorkers              = 2;
        int maxConcurrentSessions  =  -1;
        String sshRealm             = "karaf";
//        Class<?>[] roleClasses      = getClassesArray(new String[] { "org.apache.karaf.jaas.boot.principal.RolePrincipal"});
        String sshRole              = null;
        String serverPrivateKeyPath = "host.key";
        String privateKeyPassword   = null;
        String serverPublicKeyPath  = "host.key.pub";
        String[] authMethods        = new String[] {"keyboard-interactive", "password", "publickey"};
        int keySize                 = 2048;
        String algorithm            = "RSA";
        String[] macs               = new String[] {"hmac-sha2-512", "hmac-sha2-256"};
        String[] ciphers            = new String[] {"aes256-ctr", "aes192-ctr", "aes128-ctr"};
        String[] kexAlgorithms      = new String[] {"ecdh-sha2-nistp521", "ecdh-sha2-nistp384", "ecdh-sha2-nistp256", "diffie-hellman-group-exchange-sha256"};
        String[] sigAlgorithms      = new String[] {"ssh-rsa", "rsa-sha2-256", "rsa-sha2-512", "sk-ecdsa-sha2-nistp256@openssh.com", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521"};
        String welcomeBanner        = null;
        String moduliUrl            = null;
        boolean sftpEnabled         = true;

        SshServer server = SshServer.setUpDefaultServer();
        server.setPort(sshPort);
        server.setHost(sshHost);
        server.setMacFactories(SshUtils.buildMacs(macs));
        server.setCipherFactories(SshUtils.buildCiphers(ciphers));
        server.setKeyExchangeFactories(SshUtils.buildKexAlgorithms(kexAlgorithms));
        server.setSignatureFactories(SshUtils.buildSigAlgorithms(sigAlgorithms));



//        if (EnvironmentUtils.isWindows()) {
            server.setShellFactory(new ProcessShellFactory());
//        } else {
//            server.setShellFactory(new ProcessShellFactory(new String[] { "/bin/sh", "-i", "-s" }));
//        }
        server.setCommandFactory(new ProcessShellCommandFactory());

        if (sftpEnabled) {
//            server.setCommandFactory(new ScpCommandFactory.Builder().build());
            server.setSubsystemFactories(Collections.singletonList(new SftpSubsystemFactory()));
            server.setFileSystemFactory(new VirtualFileSystemFactory(Paths.get("")));
        }
//        else {
//            server.setCommandFactory((channel, cmd) -> new ShellCommand(sessionFactory, cmd));
//        }

        server.setKeyPairProvider(new FileKeyPairProvider(Paths.get(serverPrivateKeyPath)));
        server.setPasswordAuthenticator(AcceptAllPasswordAuthenticator.INSTANCE);
        server.setPublickeyAuthenticator(AcceptAllPublickeyAuthenticator.INSTANCE);
//        server.setUserAuthFactories(authFactoriesFactory.getFactories());
        server.setAgentFactory(KarafAgentFactory.getInstance());
        server.setForwardingFilter(AcceptAllForwardingFilter.INSTANCE);
        CoreModuleProperties.IDLE_TIMEOUT.set(server, Duration.ofMillis(sshIdleTimeout));
        CoreModuleProperties.NIO_WORKERS.set(server, nioWorkers);
        if (maxConcurrentSessions != -1) {
            CoreModuleProperties.MAX_CONCURRENT_SESSIONS.set(server, maxConcurrentSessions);
        }
        if (moduliUrl != null) {
            CoreModuleProperties.MODULI_URL.set(server, moduliUrl);
        }
        if (welcomeBanner != null) {
            CoreModuleProperties.WELCOME_BANNER.set(server, welcomeBanner);
        }
        return server;
    }


/*    protected static Class<?>[] getClassesArray(String[] stringArray) {
        final ClassLoader loader = Thread.currentThread().getContextClassLoader();
        return Stream.of(stringArray)
                .map(it -> {
                    try {
                        return loader.loadClass(it.trim());
                    } catch (final ClassNotFoundException e) {
                        throw new IllegalArgumentException(e);
                    }
                })
                .toArray(Class[]::new);
    }*/

}
