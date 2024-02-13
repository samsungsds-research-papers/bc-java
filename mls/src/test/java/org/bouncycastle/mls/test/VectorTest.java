package org.bouncycastle.mls.test;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import junit.framework.TestCase;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.mls.GroupKeySet;
import org.bouncycastle.mls.KeyGeneration;
import org.bouncycastle.mls.KeyScheduleEpoch;
import org.bouncycastle.mls.TranscriptHash;
import org.bouncycastle.mls.TreeKEM.LeafIndex;
import org.bouncycastle.mls.TreeKEM.LeafNode;
import org.bouncycastle.mls.TreeKEM.NodeIndex;
import org.bouncycastle.mls.TreeKEM.TreeKEMPrivateKey;
import org.bouncycastle.mls.TreeKEM.TreeKEMPublicKey;
import org.bouncycastle.mls.TreeSize;
import org.bouncycastle.mls.codec.AuthenticatedContent;
import org.bouncycastle.mls.codec.Commit;
import org.bouncycastle.mls.codec.Extension;
import org.bouncycastle.mls.codec.GroupContext;
import org.bouncycastle.mls.codec.GroupInfo;
import org.bouncycastle.mls.codec.GroupSecrets;
import org.bouncycastle.mls.codec.MLSInputStream;
import org.bouncycastle.mls.codec.MLSMessage;
import org.bouncycastle.mls.codec.MLSOutputStream;
import org.bouncycastle.mls.codec.PathSecret;
import org.bouncycastle.mls.codec.PreSharedKeyID;
import org.bouncycastle.mls.codec.Proposal;
import org.bouncycastle.mls.codec.UpdatePath;
import org.bouncycastle.mls.codec.WireFormat;
import org.bouncycastle.mls.crypto.MlsCipherSuite;
import org.bouncycastle.mls.crypto.Secret;
import org.bouncycastle.mls.protocol.Group;
import org.bouncycastle.test.TestResourceFinder;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;
import org.bouncycastle.util.encoders.Hex;

import static org.bouncycastle.mls.crypto.MlsCipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

public class VectorTest
        extends TestCase
{
    public void testTreeMath()
            throws Exception
    {
        InputStream src = TestResourceFinder.findTestResource("mls/testVectors/", "tree-math.txt");
        BufferedReader bin = new BufferedReader(new InputStreamReader(src));
        String line;
        HashMap<String, String> buf = new HashMap<String, String>();
        ArrayList<Long> left = new ArrayList<Long>();
        ArrayList<Long> right = new ArrayList<Long>();
        ArrayList<Long> parent = new ArrayList<Long>();
        ArrayList<Long> sibling = new ArrayList<Long>();
        ArrayList<Long> temp = new ArrayList<Long>();
        int arrCount = 0;


        int count = 0;

        while((line = bin.readLine())!= null)
        {
            line = line.trim();
            if (line.length() == 0)
            {
                if (buf.size() > 0)
                {
                    System.out.println("test case: " + count);
                    long n_leaves = Long.parseLong((String)buf.get("n_leaves"));
                    long n_nodes = Long.parseLong((String)buf.get("n_nodes"));
                    long root = Long.parseLong((String)buf.get("root"));
                    TreeSize treeSize = TreeSize.forLeaves(n_leaves);

                    assertEquals(root, NodeIndex.root(treeSize).value());
                    assertEquals(n_nodes, treeSize.width());
                    for (int i = 0; i < treeSize.width(); i++)
                    {
                        NodeIndex n = new NodeIndex(i);

                        // ignoring null value checks
                        assertEquals((long)(left.get(i) == -1 ? i : left.get(i)), n.left().value());
                        assertEquals((long)(right.get(i) == -1 ? i : right.get(i)), n.right().value());
                        assertEquals(parent.get(i) == -1 ? n.parent().value() : parent.get(i), n.parent().value());
                        assertEquals(sibling.get(i) == -1 ? n.sibling().value() : sibling.get(i), n.sibling().value());
                    }


                    count++;
                }
            }
            int a = line.indexOf("=");
            if (a > -1)
            {
                buf.put(line.substring(0, a).trim(), line.substring(a + 1).trim());
            }
            if (line.endsWith("START"))
            {
                while ((line = bin.readLine()) != null)
                {
                    line = line.trim();
                    if (line.endsWith("STOP"))
                    {
                        switch (arrCount)
                        {
                            case 0:
                                left = (ArrayList<Long>) temp.clone();
                                break;
                            case 1:
                                right = (ArrayList<Long>) temp.clone();
                                break;
                            case 2:
                                parent = (ArrayList<Long>) temp.clone();
                                break;
                            case 3:
                                sibling = (ArrayList<Long>) temp.clone();
                                break;
                        }
                        arrCount = (++arrCount % 4);
                        temp.clear();
                        break;
                    }
                    long val;
                    if(line.equals("null"))
                    {
                        val = -1;
                    }
                    else
                    {
                        val = Long.parseLong((String)line);
                    }
                    temp.add(val);
                }
            }
        }
    }

    public void testCryptoBasics()
            throws Exception
    {
        InputStream src = TestResourceFinder.findTestResource("mls/testVectors/", "crypto-basics.txt");
        BufferedReader bin = new BufferedReader(new InputStreamReader(src));
        String line;
        HashMap<String, String> buf = new HashMap<String, String>();
        int arrCount = 0;


        int count = 0;

        while((line = bin.readLine())!= null)
        {
            line = line.trim();
            if (line.length() == 0)
            {
                if (buf.size() > 0)
                {
                    System.out.println("test case: " + count);
                    short cipherSuite = Short.parseShort(buf.get("cipherSuite"));
                    String refHash_label = buf.get("refHash_label");
                    byte[] refHash_value = Hex.decode(buf.get("refHash_value"));
                    byte[] refHash_out = Hex.decode(buf.get("refHash_out"));

                    byte[] expandWithLabel_secret = Hex.decode(buf.get("expandWithLabel_secret"));
                    String expandWithLabel_label = buf.get("expandWithLabel_label");
                    byte[] expandWithLabel_context = Hex.decode(buf.get("expandWithLabel_context"));
                    short expandWithLabel_length = Short.parseShort(buf.get("expandWithLabel_length"));
                    byte[] expandWithLabel_out = Hex.decode(buf.get("expandWithLabel_out"));

                    byte[] deriveSecret_secret = Hex.decode(buf.get("deriveSecret_secret"));
                    String deriveSecret_label = buf.get("deriveSecret_label");
                    byte[] deriveSecret_out = Hex.decode(buf.get("deriveSecret_out"));

                    byte[] deriveTreeSecret_secret = Hex.decode(buf.get("deriveTreeSecret_secret"));
                    String deriveTreeSecret_label = buf.get("deriveTreeSecret_label");
                    int deriveTreeSecret_generation = Integer.parseUnsignedInt(buf.get("deriveTreeSecret_generation"));
                    short deriveTreeSecret_length = Short.parseShort(buf.get("deriveTreeSecret_length"));
                    byte[] deriveTreeSecret_out = Hex.decode(buf.get("deriveTreeSecret_out"));

                    byte[] signWithLabel_priv = Hex.decode(buf.get("signWithLabel_priv"));
                    byte[] signWithLabel_pub = Hex.decode(buf.get("signWithLabel_pub"));
                    byte[] signWithLabel_content = Hex.decode(buf.get("signWithLabel_content"));
                    String signWithLabel_label = buf.get("signWithLabel_label");
                    byte[] signWithLabel_signature = Hex.decode(buf.get("signWithLabel_signature"));

                    byte[] encryptWithLabel_priv = Hex.decode(buf.get("encryptWithLabel_priv"));
                    byte[] encryptWithLabel_pub = Hex.decode(buf.get("encryptWithLabel_pub"));
                    String encryptWithLabel_label = buf.get("encryptWithLabel_label");
                    byte[] encryptWithLabel_context = Hex.decode(buf.get("encryptWithLabel_context"));
                    byte[] encryptWithLabel_plaintext = Hex.decode(buf.get("encryptWithLabel_plaintext"));
                    byte[] encryptWithLabel_kemOutput = Hex.decode(buf.get("encryptWithLabel_kemOutput"));
                    byte[] encryptWithLabel_ciphertext = Hex.decode(buf.get("encryptWithLabel_ciphertext"));

                    MlsCipherSuite suite = MlsCipherSuite.getSuite(cipherSuite);

                    // ref_hash: out == RefHash(label, value)
                    byte[] refOut = suite.refHash( refHash_value, refHash_label);
                    assertTrue(Arrays.areEqual(refHash_out, refOut));

                    // expand_with_label: out == ExpandWithLabel(secret, label, context, length)
                    byte[] expandWithLabelOut = suite.getKDF().expandWithLabel(expandWithLabel_secret, expandWithLabel_label, expandWithLabel_context, expandWithLabel_length);
                    assertTrue(Arrays.areEqual(expandWithLabel_out, expandWithLabelOut));

                    // Using Secret Class
                    Secret secret = new Secret(expandWithLabel_secret);
                    expandWithLabelOut = secret.expandWithLabel(suite, expandWithLabel_label, expandWithLabel_context, expandWithLabel_length).value();
                    assertTrue(Arrays.areEqual(expandWithLabel_out, expandWithLabelOut));


                    // derive_secret: out == DeriveSecret(secret, label)
                    byte[] deriveSecretOut = suite.getKDF().expandWithLabel(deriveSecret_secret, deriveSecret_label, new byte[] {}, suite.getKDF().getHashLength());
                    assertTrue(Arrays.areEqual(deriveSecret_out, deriveSecretOut));

                    // Using Secret Class
                    secret = new Secret(deriveSecret_secret);
                    deriveSecretOut = secret.deriveSecret(suite, deriveSecret_label).value();
                    assertTrue(Arrays.areEqual(deriveSecret_out, deriveSecretOut));


                    // derive_tree_secret: out == DeriveTreeSecret(secret, label, generation, length)
                    byte[] deriveTreeSecretOut = suite.getKDF().expandWithLabel(deriveTreeSecret_secret, deriveTreeSecret_label, Pack.intToBigEndian(deriveTreeSecret_generation), deriveTreeSecret_length);
                    assertTrue(Arrays.areEqual(deriveTreeSecret_out, deriveTreeSecretOut));

                    // Using Secret class
                    secret = new Secret(deriveTreeSecret_secret);
                    deriveTreeSecretOut = secret.deriveTreeSecret(suite, deriveTreeSecret_label, deriveTreeSecret_generation, deriveTreeSecret_length).value();
                    assertTrue(Arrays.areEqual(deriveTreeSecret_out, deriveTreeSecretOut));


                    // sign_with_label:
                    //      VerifyWithLabel(pub, label, content, signature) == true
                    boolean verifyWithLabel = suite.verifyWithLabel(signWithLabel_pub, signWithLabel_label, signWithLabel_content, signWithLabel_signature);
                    assertTrue(verifyWithLabel);
                    //      VerifyWithLabel(pub, label, content, SignWithLabel(priv, label, content)) == true
                    byte[] signatureWithLabel = suite.signWithLabel(signWithLabel_priv, signWithLabel_label, signWithLabel_content);
                    verifyWithLabel = suite.verifyWithLabel(signWithLabel_pub, signWithLabel_label, signWithLabel_content, signatureWithLabel);
                    assertTrue(verifyWithLabel);


                    // encrypt_with_label:
                    //      DecryptWithLabel(priv, label, context, kem_output, ciphertext) == plaintext
                    byte[] plaintextOut = suite.decryptWithLabel(encryptWithLabel_priv, encryptWithLabel_label, encryptWithLabel_context, encryptWithLabel_kemOutput, encryptWithLabel_ciphertext);
                    assertTrue(Arrays.areEqual(plaintextOut, encryptWithLabel_plaintext));
                    //      kem_output_candidate, ciphertext_candidate = EncryptWithLabel(pub, label, context, plaintext)
                    byte[][] encryptWithLabelOut = suite.encryptWithLabel(encryptWithLabel_pub, encryptWithLabel_label, encryptWithLabel_context, encryptWithLabel_plaintext);
                    byte[] kem_output_candidate = encryptWithLabelOut[1];
                    byte[] ciphertext_candidate = encryptWithLabelOut[0];
                    //      DecryptWithLabel(priv, label, context, kem_output_candidate, ciphertext_candidate) == plaintext
                    plaintextOut = suite.decryptWithLabel(encryptWithLabel_priv, encryptWithLabel_label, encryptWithLabel_context, kem_output_candidate, ciphertext_candidate);
                    assertTrue(Arrays.areEqual(plaintextOut, encryptWithLabel_plaintext));

                    count++;
                }
            }
            int a = line.indexOf("=");
            if (a > -1)
            {
                buf.put(line.substring(0, a).trim(), line.substring(a + 1).trim());
            }
        }

    }

    public void testSecretTree()
            throws Exception
    {
        class LeafInfo
        {
            int generation;
            byte[] application_key;
            byte[] application_nonce;
            byte[] handshake_key;
            byte[] handshake_nonce;

            public LeafInfo(int generation, byte[] application_key, byte[] application_nonce, byte[] handshake_key, byte[] handshake_nonce)
            {
                this.generation = generation;
                this.application_key = application_key;
                this.application_nonce = application_nonce;
                this.handshake_key = handshake_key;
                this.handshake_nonce = handshake_nonce;
            }
        }

        InputStream src = TestResourceFinder.findTestResource("mls/testVectors/", "secret-tree.txt");
        BufferedReader bin = new BufferedReader(new InputStreamReader(src));
        String line;
        HashMap<String, String> buf = new HashMap<String, String>();
        HashMap<String, String> bufLeaf = new HashMap<String, String>();
        ArrayList<LeafInfo[]> leaves = new ArrayList<LeafInfo[]>();
        int leafCounter = 0;
        LeafInfo[] tempLeaf = null;
        int count = 0;

        while((line = bin.readLine())!= null)
        {
            line = line.trim();
            if (line.length() == 0)
            {
                if (buf.size() > 0)
                {
                    System.out.println("test case: " + count);
                    short cipher_suite = Short.parseShort(buf.get("cipher_suite"));
                    byte[] encryption_secret = Hex.decode(buf.get("encryption_secret"));
                    byte[] sender_data_secret = Hex.decode(buf.get("sender_data_secret"));
                    byte[] ciphertext = Hex.decode(buf.get("ciphertext"));
                    byte[] key = Hex.decode(buf.get("key"));
                    byte[] nonce = Hex.decode(buf.get("nonce"));
                    MlsCipherSuite suite = MlsCipherSuite.getSuite(cipher_suite);

                    // sender_data:
                    //      key == sender_data_key(sender_data_secret, ciphertext)
                    byte[] ciphertext_sample = Arrays.copyOf(ciphertext, suite.getKDF().getHashLength());
                    byte[] sender_data_key = suite.getKDF().expandWithLabel(sender_data_secret, "key", ciphertext_sample, suite.getAEAD().getKeySize());
                    assertTrue(Arrays.areEqual(sender_data_key, key));
                    //      nonce == sender_data_nonce(sender_data_secret, ciphertext)
                    byte[] sender_data_nonce = suite.getKDF().expandWithLabel(sender_data_secret, "nonce", ciphertext_sample, suite.getAEAD().getNonceSize());
                    assertTrue(Arrays.areEqual(sender_data_nonce, nonce));

                    // Initialize a secret tree with a number of leaves equal to the number of entries
                    // in the leaves array, with encryption_secret as the root secret
                    TreeSize treeSize = TreeSize.forLeaves(leaves.size());
                    Secret root = new Secret(encryption_secret);
                    GroupKeySet keys = new GroupKeySet(suite, treeSize, root);


                    // For each entry in the array leaves[i], verify that:
                    //      handshake_key = handshake_ratchet_key_[i]_[generation]
                    //      handshake_nonce = handshake_ratchet_nonce_[i]_[generation]
                    //      application_key = application_ratchet_key_[i]_[generation]
                    //      application_nonce = application_ratchet_nonce_[i]_[generation]
                    for (int i = 0; i < leaves.size(); i++)
                    {
                        for (LeafInfo leafinfo: leaves.get(i))
                        {
                            LeafIndex leafNode = new LeafIndex(i);
                            KeyGeneration hsGen = keys.handshakeRatchet(leafNode).get(leafinfo.generation);
                            KeyGeneration appGen = keys.applicationRatchet(leafNode).get(leafinfo.generation);

                            assertTrue(Arrays.areEqual(hsGen.key, leafinfo.handshake_key));
                            assertTrue(Arrays.areEqual(hsGen.nonce, leafinfo.handshake_nonce));
                            assertTrue(Arrays.areEqual(appGen.key, leafinfo.application_key));
                            assertTrue(Arrays.areEqual(appGen.nonce, leafinfo.application_nonce));
                        }
                    }

                    buf.clear();
                    leaves.clear();
                    count++;
                }
            }
            int a = line.indexOf("=");
            if (a > -1)
            {
                buf.put(line.substring(0, a).trim(), line.substring(a + 1).trim());
            }
            if (line.endsWith("START"))
            {
                while ((line = bin.readLine()) != null)
                {
                    line = line.trim();
                    if(line.endsWith("STOP"))
                    {
                        break;
                    }
                    if (line.length() == 0)
                    {
                        if (bufLeaf.size() > 0)
                        {

                            int generation = Integer.parseUnsignedInt(bufLeaf.get("generation"));
                            byte[] application_key = Hex.decode(bufLeaf.get("application_key"));
                            byte[] application_nonce = Hex.decode(bufLeaf.get("application_nonce"));
                            byte[] handshake_key = Hex.decode(bufLeaf.get("handshake_key"));
                            byte[] handshake_nonce = Hex.decode(bufLeaf.get("handshake_nonce"));
                            if(leafCounter == 0)
                            {
                                tempLeaf = new LeafInfo[2];
                            }
                            tempLeaf[leafCounter] = new LeafInfo(generation, application_key, application_nonce, handshake_key, handshake_nonce);
                            if (leafCounter == 1)
                            {
                                leaves.add(tempLeaf);
                            }

                            leafCounter = (++leafCounter)%2;
                            bufLeaf.clear();
                        }
                    }
                    int b = line.indexOf("=");
                    if (b > -1)
                    {
                        bufLeaf.put(line.substring(0, b).trim(), line.substring(b + 1).trim());
                    }
                }
            }
        }
    }

    public void testKeySchedule()
            throws Exception
    {
        InputStream src = TestResourceFinder.findTestResource("mls/testVectors/", "key-schedule.txt");
        BufferedReader bin = new BufferedReader(new InputStreamReader(src));
        String line;
        HashMap<String, String> buf = new HashMap<String, String>();
        HashMap<String, String> bufEpoch = new HashMap<String, String>();
        Secret prevEpochSecret = null;
        int count = 0;
        int epochCount = 0;

        while((line = bin.readLine())!= null)
        {
            line = line.trim();
            if (line.length() == 0)
            {
                if (buf.size() > 0)
                {
                    System.out.println("test case: " + count);
                    buf.clear();
                    bufEpoch.clear();
                    count++;
                    epochCount = 0;

                }
            }
            int a = line.indexOf("=");
            if (a > -1)
            {
                buf.put(line.substring(0, a).trim(), line.substring(a + 1).trim());
            }
            if (line.endsWith("START"))
            {
                while ((line = bin.readLine()) != null)
                {
                    line = line.trim();
                    if(line.endsWith("STOP"))
                    {

                        break;
                    }
                    if (line.length() == 0)
                    {
                        if (bufEpoch.size() > 0)
                        {
//                            System.out.println("test case: " + count + " epoch: " + epochCount );
                            byte[] commit_secret = Hex.decode(bufEpoch.get("commit_secret"));
                            byte[] confirmation_key = Hex.decode(bufEpoch.get("confirmation_key"));
                            byte[] confirmed_transcript_hash = Hex.decode(bufEpoch.get("confirmed_transcript_hash"));
                            byte[] encryption_secret = Hex.decode(bufEpoch.get("encryption_secret"));
                            byte[] epoch_authenticator = Hex.decode(bufEpoch.get("epoch_authenticator"));
                            byte[] exporterContext = Hex.decode(bufEpoch.get("exporterContext"));
                            String exporterLabel = bufEpoch.get("exporterLabel");
                            int exporterLength = Integer.parseInt(bufEpoch.get("exporterLength"));
                            byte[] exporterSecret = Hex.decode(bufEpoch.get("exporterSecret"));
                            byte[] exporter_secret = Hex.decode(bufEpoch.get("exporter_secret"));
                            byte[] external_pub = Hex.decode(bufEpoch.get("external_pub"));
                            byte[] external_secret = Hex.decode(bufEpoch.get("external_secret"));
                            byte[] group_context = Hex.decode(bufEpoch.get("group_context"));
                            byte[] init_secret = Hex.decode(bufEpoch.get("init_secret"));
                            byte[] joiner_secret = Hex.decode(bufEpoch.get("joiner_secret"));
                            byte[] membership_key = Hex.decode(bufEpoch.get("membership_key"));
                            byte[] psk_secret = Hex.decode(bufEpoch.get("psk_secret"));
                            byte[] resumption_psk = Hex.decode(bufEpoch.get("resumption_psk"));
                            byte[] sender_data_secret = Hex.decode(bufEpoch.get("sender_data_secret"));
                            byte[] tree_hash = Hex.decode(bufEpoch.get("tree_hash"));
                            byte[] welcome_secret = Hex.decode(bufEpoch.get("welcome_secret"));

                            short cipher_suite = Short.parseShort(buf.get("cipher_suite"));
                            byte[] group_id = Hex.decode(buf.get("group_id"));
                            byte[] initial_init_secret = Hex.decode(buf.get("initial_init_secret"));
                            MlsCipherSuite suite = MlsCipherSuite.getSuite(cipher_suite);

                            GroupContext groupContext = new GroupContext(
                                    suite,
                                    group_id,
                                    epochCount,
                                    tree_hash,
                                    confirmed_transcript_hash,
                                    new ArrayList<Extension>()
                            );
                            // Verify that group context matches the provided group_context value
                            byte[] groupContextBytes = MLSOutputStream.encode(groupContext);
                            assertTrue(Arrays.areEqual(group_context, groupContextBytes));

                            // Initialize the creator's key schedule
                            TreeSize treeSize = TreeSize.forLeaves(1+epochCount);
                            KeyScheduleEpoch.JoinSecrets joinSecrets;
                            if(epochCount == 0)
                            {
                                prevEpochSecret = new Secret(initial_init_secret);
                            }

                            joinSecrets = KeyScheduleEpoch.JoinSecrets.forMember(suite, prevEpochSecret, new Secret(commit_secret), new Secret(new byte[0]), group_context);
                            joinSecrets.injectPskSecret(new Secret(psk_secret));
                            assertTrue(Arrays.areEqual(joiner_secret, joinSecrets.joinerSecret.value()));
                            assertTrue(Arrays.areEqual(welcome_secret, joinSecrets.welcomeSecret.value()));

                            KeyScheduleEpoch epoch = joinSecrets.complete(treeSize, group_context);
                            prevEpochSecret = epoch.initSecret;
                            assertTrue(Arrays.areEqual(init_secret, epoch.initSecret.value()));
                            assertTrue(Arrays.areEqual(sender_data_secret, epoch.senderDataSecret.value()));
                            assertTrue(Arrays.areEqual(encryption_secret, epoch.encryptionSecret.value()));
                            assertTrue(Arrays.areEqual(exporter_secret, epoch.exporterSecret.value()));
                            assertTrue(Arrays.areEqual(epoch_authenticator, epoch.epochAuthenticator.value()));
                            assertTrue(Arrays.areEqual(external_secret, epoch.externalSecret.value()));
                            assertTrue(Arrays.areEqual(confirmation_key, epoch.confirmationKey.value()));
                            assertTrue(Arrays.areEqual(membership_key, epoch.membershipKey.value()));
                            assertTrue(Arrays.areEqual(resumption_psk, epoch.resumptionPSK.value()));

                            byte[] externalPubBytes = suite.getHPKE().serializePublicKey(epoch.getExternalPublicKey());
                            assertTrue(Arrays.areEqual(external_pub, externalPubBytes));

                            byte[] exporterSecretBytes = epoch.MLSExporter(exporterLabel, exporterContext, exporterLength);
                            assertTrue(Arrays.areEqual(exporterSecret, exporterSecretBytes));




                            epochCount++;
                            bufEpoch.clear();
                        }
                    }
                    int b = line.indexOf("=");
                    if (b > -1)
                    {
                        bufEpoch.put(line.substring(0, b).trim(), line.substring(b + 1).trim());
                    }
                }
            }
        }
    }

    public void testPskSecret()
            throws Exception
    {
        class PSK
        {
            final byte[] psk_id;
            final byte[] psk;
            final byte[] psk_nonce;

            public PSK(byte[] psk_id, byte[] psk, byte[] psk_nonce)
            {
                this.psk_id = psk_id;
                this.psk = psk;
                this.psk_nonce = psk_nonce;
            }
        }
        InputStream src = TestResourceFinder.findTestResource("mls/testVectors/", "psk_secret.txt");
        BufferedReader bin = new BufferedReader(new InputStreamReader(src));
        String line;
        HashMap<String, String> buf = new HashMap<String, String>();
        HashMap<String, String> bufpsk = new HashMap<String, String>();
        ArrayList<PSK> psks = new ArrayList<PSK>();
        int count = 0;

        while((line = bin.readLine())!= null)
        {
            line = line.trim();
            if (line.length() == 0)
            {
                if (buf.size() > 0)
                {
                    System.out.println("test case: " + count);
                    short cipher_suite = Short.parseShort(buf.get("cipher_suite"));
                    byte[] psk_secret = Hex.decode(buf.get("psk_secret"));
                    MlsCipherSuite suite = MlsCipherSuite.getSuite(cipher_suite);

                    List<KeyScheduleEpoch.PSKWithSecret> pskList = new ArrayList<KeyScheduleEpoch.PSKWithSecret>();
                    for (PSK psk : psks)
                    {
                        PreSharedKeyID external = PreSharedKeyID.external(psk.psk_id, psk.psk_nonce);
                        KeyScheduleEpoch.PSKWithSecret temp = new KeyScheduleEpoch.PSKWithSecret(external, new Secret(psk.psk));
                        pskList.add(temp);
                    }

                    Secret pskOutput = KeyScheduleEpoch.JoinSecrets.pskSecret(suite, pskList);
                    assertTrue(Arrays.areEqual(psk_secret, pskOutput.value()));

                    buf.clear();
                    psks.clear();
                    count++;
                }
            }
            int a = line.indexOf("=");
            if (a > -1)
            {
                buf.put(line.substring(0, a).trim(), line.substring(a + 1).trim());
            }
            if (line.endsWith("START"))
            {
                while ((line = bin.readLine()) != null)
                {
                    line = line.trim();
                    if(line.endsWith("STOP"))
                    {
                        break;
                    }
                    if (line.length() == 0)
                    {
                        if (bufpsk.size() > 0)
                        {

                            byte[] psk_id = Hex.decode(bufpsk.get("psk_id"));
                            byte[] psk = Hex.decode(bufpsk.get("psk"));
                            byte[] psk_nonce = Hex.decode(bufpsk.get("psk_nonce"));

                            psks.add(new PSK(psk_id, psk, psk_nonce));
                            bufpsk.clear();
                        }
                    }
                    int b = line.indexOf("=");
                    if (b > -1)
                    {
                        bufpsk.put(line.substring(0, b).trim(), line.substring(b + 1).trim());
                    }
                }
            }
        }
    }

    public void testTranscriptHashes()
            throws Exception
    {
        InputStream src = TestResourceFinder.findTestResource("mls/testVectors/", "transcript-hashes.txt");
        BufferedReader bin = new BufferedReader(new InputStreamReader(src));
        String line;
        HashMap<String, String> buf = new HashMap<String, String>();
        int count = 0;

        while((line = bin.readLine())!= null)
        {
            line = line.trim();
            if (line.length() == 0)
            {
                if (buf.size() > 0)
                {
                    System.out.println("test case: " + count);
                    short cipherSuite = Short.parseShort(buf.get("cipher_suite"));
                    byte[] confirmation_key = Hex.decode(buf.get("confirmation_key"));
                    byte[] authenticated_content = Hex.decode(buf.get("authenticated_content"));
                    byte[] interim_transcript_hash_before = Hex.decode(buf.get("interim_transcript_hash_before"));
                    byte[] confirmed_transcript_hash_after = Hex.decode(buf.get("confirmed_transcript_hash_after"));
                    byte[] interim_transcript_hash_after = Hex.decode(buf.get("interim_transcript_hash_after"));

                    MlsCipherSuite suite = MlsCipherSuite.getSuite(cipherSuite);
                    TranscriptHash transcript = new TranscriptHash(suite);
                    transcript.setInterim(interim_transcript_hash_before);

                    AuthenticatedContent authContent = (AuthenticatedContent) MLSInputStream.decode(authenticated_content, AuthenticatedContent.class);
                    transcript.update(authContent);
                    assertTrue(Arrays.areEqual(transcript.getConfirmed(), confirmed_transcript_hash_after));
                    assertTrue(Arrays.areEqual(transcript.getInterim(), interim_transcript_hash_after));

                    byte[] confirmationTag = suite.getKDF().extract(confirmation_key, transcript.getConfirmed());
                    assertTrue(Arrays.areEqual(confirmationTag, authContent.getConfirmationTag()));

                    count++;
                }
            }
            int a = line.indexOf("=");
            if (a > -1)
            {
                buf.put(line.substring(0, a).trim(), line.substring(a + 1).trim());
            }
        }
    }
    public void testWelcome()
            throws Exception
    {
        InputStream src = TestResourceFinder.findTestResource("mls/testVectors/", "welcome.txt");
        BufferedReader bin = new BufferedReader(new InputStreamReader(src));
        String line;
        HashMap<String, String> buf = new HashMap<String, String>();
        int count = 0;

        while((line = bin.readLine())!= null)
        {
            line = line.trim();
            if (line.length() == 0)
            {
                if (buf.size() > 0)
                {
                    System.out.println("test case: " + count);
                    short cipherSuite = Short.parseShort(buf.get("cipher_suite"));
                    byte[] init_priv = Hex.decode(buf.get("init_priv"));
                    byte[] key_package = Hex.decode(buf.get("key_package"));
                    byte[] signer_pub = Hex.decode(buf.get("signer_pub"));
                    byte[] welcome = Hex.decode(buf.get("welcome"));

                    MlsCipherSuite suite = MlsCipherSuite.getSuite(cipherSuite);

                    MLSMessage welcomeMessage = (MLSMessage) MLSInputStream.decode(welcome, MLSMessage.class);

                    // Sanity check
                    byte[] welcomeBytes = MLSOutputStream.encode(welcomeMessage);
                    assertTrue(Arrays.areEqual(welcomeBytes, welcome));
                    assertEquals(welcomeMessage.wireFormat, WireFormat.mls_welcome);

                    MLSMessage kpMessage = (MLSMessage) MLSInputStream.decode(key_package, MLSMessage.class);
                    assertEquals(kpMessage.wireFormat, WireFormat.mls_key_package);

                    // Sanity check
                    byte[] kpBytes = MLSOutputStream.encode(kpMessage);
                    assertTrue(Arrays.areEqual(kpBytes, key_package));

                    assertEquals(kpMessage.getCipherSuite().getSuiteID(), cipherSuite);
                    assertEquals(kpMessage.getCipherSuite().getSuiteID(), cipherSuite);

                    int kpi = welcomeMessage.welcome.find(kpMessage.keyPackage);
                    assertTrue(kpi != -1);
                    GroupSecrets groupSecrets = welcomeMessage.welcome.decryptSecrets(kpi, init_priv);
                    GroupInfo groupInfo = welcomeMessage.welcome.decrypt(groupSecrets.joiner_secret, new ArrayList<KeyScheduleEpoch.PSKWithSecret>());

                    boolean verified = groupInfo.verify(suite, signer_pub);
                    assertTrue(verified);

                    GroupContext groupContext = groupInfo.getGroupContext();
                    KeyScheduleEpoch keySchedule = KeyScheduleEpoch.joiner(
                            suite,
                            groupSecrets.joiner_secret,
                            new ArrayList<KeyScheduleEpoch.PSKWithSecret>(),
                            MLSOutputStream.encode(groupContext));


                    byte[] confirmationTag = keySchedule.confirmationTag(groupContext.getConfirmedTranscriptHash());
                    assertTrue(Arrays.areEqual(confirmationTag, groupInfo.getConfirmationTag()));

                    count++;
                }
            }
            int a = line.indexOf("=");
            if (a > -1)
            {
                buf.put(line.substring(0, a).trim(), line.substring(a + 1).trim());
            }
        }
    }

    public void testTreeOperations() throws Exception
    {
        InputStream src = TestResourceFinder.findTestResource("mls/testVectors/", "tree-operations.txt");
        BufferedReader bin = new BufferedReader(new InputStreamReader(src));
        String line;
        HashMap<String, String> buf = new HashMap<String, String>();
        int count = 0;

        while((line = bin.readLine())!= null)
        {
            line = line.trim();
            if (line.length() == 0)
            {
                if (buf.size() > 0)
                {

                    System.out.println("test case: " + count);
                    byte[] tree_before = Hex.decode(buf.get("tree_before"));
                    byte[] proposal = Hex.decode(buf.get("proposal"));
                    int proposal_sender = Integer.parseInt(buf.get("proposal_sender"));
                    byte[] tree_after = Hex.decode(buf.get("tree_after"));

                    MlsCipherSuite suite = MlsCipherSuite.getSuite(MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519);

                    TreeKEMPublicKey beforeTree = (TreeKEMPublicKey) MLSInputStream.decode(tree_before, TreeKEMPublicKey.class);
                    TreeKEMPublicKey afterTree = (TreeKEMPublicKey) MLSInputStream.decode(tree_after, TreeKEMPublicKey.class);

                    //SanityChecks
                    byte[] beforeTreeBytes = MLSOutputStream.encode(beforeTree);
                    assertTrue(Arrays.areEqual(tree_before, beforeTreeBytes));
                    byte[] afterTreeBytes = MLSOutputStream.encode(afterTree);
                    assertTrue(Arrays.areEqual(tree_after, afterTreeBytes));

                    beforeTree.setSuite(suite);
                    beforeTree.setHashAll();

                    Proposal proposalObj = (Proposal) MLSInputStream.decode(proposal, Proposal.class);
                    switch (proposalObj.getProposalType())
                    {
                        case ADD:
                            beforeTree.addLeaf(proposalObj.getLeafNode());
                            break;
                        case UPDATE:
                            beforeTree.updateLeaf(new LeafIndex(proposal_sender), proposalObj.getLeafNode());
                            break;
                        case REMOVE:
                            beforeTree.blankPath(proposalObj.getRemove().removed);
                            beforeTree.truncate();
                            break;
                    }

//                    System.out.print("NewBefore");
//                    beforeTree.dump();

                    byte[] treeBytes = MLSOutputStream.encode(beforeTree);
                    assertTrue(Arrays.areEqual(tree_after, treeBytes));

                    count++;
                }
            }
            int a = line.indexOf("=");
            if (a > -1)
            {
                buf.put(line.substring(0, a).trim(), line.substring(a + 1).trim());
            }
        }
    }

    public void testTreeValidation()
            throws Exception
    {
        InputStream src = TestResourceFinder.findTestResource("mls/testVectors/", "tree-validation.txt");
        BufferedReader bin = new BufferedReader(new InputStreamReader(src));
        String line;
        HashMap<String, String> buf = new HashMap<String, String>();
        ArrayList<byte[]> hashes = new ArrayList<byte[]>();
        ArrayList<ArrayList<NodeIndex>> resolution = new ArrayList<ArrayList<NodeIndex>>();
        ArrayList<NodeIndex> temp = new ArrayList<NodeIndex>();
        int count = 0;

        while((line = bin.readLine())!= null)
        {
            line = line.trim();
            if (line.length() == 0)
            {
                if (buf.size() > 0)
                {
                    System.out.println("test case: " + count);
                    short cipherSuite = Short.parseShort(buf.get("cipher_suite"));
                    byte[] treeBytes = Hex.decode(buf.get("tree"));
                    byte[] group_id = Hex.decode(buf.get("group_id"));

                    MlsCipherSuite suite = MlsCipherSuite.getSuite(cipherSuite);
                    TreeKEMPublicKey tree = (TreeKEMPublicKey) MLSInputStream.decode(treeBytes, TreeKEMPublicKey.class);
                    tree.setSuite(suite);
                    tree.setHashAll();
//                    tree.dump();

                    // Verify each leaf node is properly signed
                    for (int i = 0; i < tree.getSize().leafCount(); i++)
                    {
                        LeafNode leaf = tree.getLeafNode(new LeafIndex(i));
                        if (leaf == null)
                        {
                            continue;
                        }

                        boolean leafValid = leaf.verify(suite, leaf.toBeSigned(group_id, i));
                        assertTrue(leafValid);
                    }

                    // Verify the tree hashes
                    for (int i = 0; i < tree.getSize().width(); i++)
                    {
                        NodeIndex index = new NodeIndex(i);
                        // Tree hash
                        assertTrue(Arrays.areEqual(tree.getHash(index), hashes.get(i)));
                        // Resolution
                        assertEquals(tree.resolve(index), resolution.get(i));
                    }

                    // Verify parent hashes
                    assertTrue(tree.verifyParentHash());

                    // verify resolutions
                    for (int i = 0; i < tree.getSize().width(); i++)
                    {
                        NodeIndex n = new NodeIndex(i);
                        assertEquals(tree.resolve(n), resolution.get(i));
                    }

                    hashes.clear();
                    resolution.clear();
                    count++;
                }
            }
            int a = line.indexOf("=");
            if (a > -1)
            {
                buf.put(line.substring(0, a).trim(), line.substring(a + 1).trim());
            }

            // Read Hashes
            if (line.endsWith("START"))
            {
                while ((line = bin.readLine()) != null)
                {
                    line = line.trim();
                    if (line.endsWith("STOP"))
                    {
                        line = bin.readLine();
                        line = bin.readLine();
                        break;
                    }
                    byte[] hash = Hex.decode(line);
                    hashes.add(hash);

                }
            }
            if (line.endsWith("START"))
            {
                while ((line = bin.readLine()) != null)
                {
                    line = line.trim();
                    if (line.endsWith("STOP"))
                    {
                        resolution.add((ArrayList<NodeIndex>) temp.clone());
                        temp.clear();
                        line = bin.readLine().trim();
                        if (line.endsWith("STOP"))
                        {
                            break;
                        }
                    }
                    if (line.endsWith("START"))
                    {
                        continue;
                    }
                    temp.add(new NodeIndex(Integer.parseInt(line)));
                }
            }
        }
    }


    public void testTreeKEM()
            throws Exception
    {
        class PathSecretInfo
        {
            NodeIndex node;
            byte[] pathSecret;

            public PathSecretInfo(NodeIndex node, byte[] pathSecret)
            {
                this.node = node;
                this.pathSecret = pathSecret;
            }
        }
        class LeafPrivateInfo
        {
            LeafIndex index;
            byte[] encryptionPriv;
            byte[] signaturePriv;
            List<PathSecretInfo> pathSecrets;

            public LeafPrivateInfo(LeafIndex index, byte[] encryptionPriv, byte[] signaturePriv, List<PathSecretInfo> pathSecrets)
            {
                this.index = index;
                this.encryptionPriv = encryptionPriv;
                this.signaturePriv = signaturePriv;
                this.pathSecrets = pathSecrets;
            }
        }

        class UpdatePathInfo
        {
            LeafIndex sender;
            UpdatePath updatePath;
            List<PathSecret> pathSecrets;
            byte[] commitSecret;
            byte[] treeHashAfter;

            public UpdatePathInfo(LeafIndex sender, UpdatePath updatePath, List<PathSecret> pathSecrets, byte[] commitSecret, byte[] treeHashAfter)
            {
                this.sender = sender;
                this.updatePath = updatePath;
                this.pathSecrets = pathSecrets;
                this.commitSecret = commitSecret;
                this.treeHashAfter = treeHashAfter;
            }
        }



        InputStream src = TestResourceFinder.findTestResource("mls/testVectors/", "treekem.txt");
        BufferedReader bin = new BufferedReader(new InputStreamReader(src));
        String line;

        String reading = "";
        String prevReading = "";
        HashMap<String, String> buf = new HashMap<String, String>();

        HashMap<String, String> bufleaf = new HashMap<String, String>();
        ArrayList<LeafPrivateInfo> privateLeaves = new ArrayList<LeafPrivateInfo>();
        ArrayList<PathSecretInfo> plPathSecrets = new ArrayList<PathSecretInfo>();

        HashMap<String, String> bufPaths = new HashMap<String, String>();
        ArrayList<UpdatePathInfo> updatePaths = new ArrayList<UpdatePathInfo>();
        ArrayList<PathSecret> upPathSecrets = new ArrayList<PathSecret>();


        int count = 0;

        while((line = bin.readLine())!= null)
        {
            line = line.trim();
            if (line.endsWith("START"))
            {
                prevReading = reading;
                reading = line.substring(0, line.indexOf("START"));
                continue;
            }
            if(line.endsWith("STOP"))
            {
                reading = prevReading;
                prevReading = "";
                continue;
            }
            if (line.length() == 0)
            {
                if (buf.size() > 0 && reading.equals(prevReading))
                {
                    System.out.println("test case: " + count);
                    short cipher_suite = Short.parseShort(buf.get("cipher_suite"));
                    byte[] confirmed_transcript_hash = Hex.decode(buf.get("confirmed_transcript_hash"));
                    long epoch = Long.parseLong(buf.get("epoch"));
                    byte[] group_id = Hex.decode(buf.get("group_id"));
                    byte[] ratchet_tree = Hex.decode(buf.get("ratchet_tree"));

                    MlsCipherSuite suite = MlsCipherSuite.getSuite(cipher_suite);
                    TreeKEMPublicKey tree = (TreeKEMPublicKey) MLSInputStream.decode(ratchet_tree, TreeKEMPublicKey.class);
                    tree.setSuite(suite);
                    tree.setHashAll();

                    // Validate the public state
                    assertTrue(tree.verifyParentHash());

                    for (int i = 0; i < tree.getSize().leafCount(); i++)
                    {
                        LeafIndex index = new LeafIndex(i);
                        LeafNode leaf = tree.getLeafNode(index);
                        if (leaf == null)
                        {
                            continue;
                        }

                        assertTrue(leaf.verify(suite, leaf.toBeSigned(group_id, i)));
                    }

                    // Import private keys
                    Map<LeafIndex, TreeKEMPrivateKey> treePrivs = new HashMap<LeafIndex, TreeKEMPrivateKey>();
                    Map<LeafIndex, byte[]> sigPrivs = new HashMap<LeafIndex, byte[]>();

                    for (LeafPrivateInfo info : privateLeaves)
                    {
                        AsymmetricCipherKeyPair encPriv = suite.getHPKE().deserializePrivateKey(info.encryptionPriv, null);
                        byte[] sigPriv = info.signaturePriv;
                        TreeKEMPrivateKey priv = new TreeKEMPrivateKey(suite, info.index);
                        priv.insertPrivateKey(new NodeIndex(info.index), encPriv);

                        for (PathSecretInfo entry : info.pathSecrets)
                        {
                            priv.insertPathSecret(entry.node, new Secret(entry.pathSecret));
                        }
                        assertTrue(priv.consistent(tree));

                        treePrivs.put(info.index, priv);
                        sigPrivs.put(info.index, sigPriv);
                    }

                    for (UpdatePathInfo info : updatePaths)
                    {
                        // Test decap of the existing group secrets
                        LeafIndex from = info.sender;
                        UpdatePath path = info.updatePath;
                        assertTrue(tree.verifyParentHash(from, path));

                        TreeKEMPublicKey treeAfter = TreeKEMPublicKey.clone(tree);
                        treeAfter.merge(from, path);
                        treeAfter.setHashAll();
                        assertTrue(Arrays.areEqual(treeAfter.getRootHash(), info.treeHashAfter));

                        GroupContext groupContext = new GroupContext(
                                suite,
                                group_id,
                                epoch,
                                treeAfter.getRootHash(),
                                confirmed_transcript_hash,
                                new ArrayList<Extension>()
                        );

                        byte[] ctx = MLSOutputStream.encode(groupContext);
                        for (int i = 0; i < treeAfter.getSize().leafCount(); i++)
                        {
                            LeafIndex to = new LeafIndex(i);
                            if (to.equals(from) || !treeAfter.hasLeaf(to))
                            {
                                continue;
                            }
                            TreeKEMPrivateKey priv = treePrivs.get(to).copy();
                            priv.decap(from, treeAfter, ctx, path, new ArrayList<LeafIndex>());

                            assertTrue(Arrays.areEqual(priv.getUpdateSecret().value(), info.commitSecret));

                            Secret sharedPathSecret = priv.getSharedPathSecret(from);
                            assertTrue(Arrays.areEqual(sharedPathSecret.value(), info.pathSecrets.get(to.value()).getPathSecret()));

                        }

                        // Test encap/decap
                        TreeKEMPublicKey encapTree = TreeKEMPublicKey.clone(tree);
                        byte[] leafSecret = new byte[suite.getKDF().getHashLength()];
//                        SecureRandom rng = new SecureRandom();
//                        rng.nextBytes(leafSecret);
                        byte[] sigPriv = sigPrivs.get(from);
                        TreeKEMPrivateKey newSenderPriv = encapTree.update(from, new Secret(leafSecret), group_id, sigPriv, new Group.LeafNodeOptions());

                        UpdatePath newPath = encapTree.encap(newSenderPriv, ctx, new ArrayList<LeafIndex>());
                        assertTrue(tree.verifyParentHash(from, path));

                        for (int i = 0; i < encapTree.getSize().leafCount(); i++)
                        {
                            LeafIndex to = new LeafIndex(i);
                            if (to.equals(from) || !encapTree.hasLeaf(to))
                            {
                                continue;
                            }

                            TreeKEMPrivateKey priv = treePrivs.get(to).copy();
                            priv.decap(from, encapTree, ctx, newPath, new ArrayList<LeafIndex>());

                            assertTrue(Arrays.areEqual(priv.getUpdateSecret().value(), newSenderPriv.getUpdateSecret().value()));
                        }


                    }


                    buf.clear();
                    privateLeaves.clear();
                    count++;
                }
                if (bufleaf.size() > 0 && !prevReading.equals("leaves_private"))
                {

                    int index = Integer.parseInt(bufleaf.get("index"));
                    byte[] encryption_priv = Hex.decode(bufleaf.get("encryption_priv"));
                    byte[] signature_priv = Hex.decode(bufleaf.get("signature_priv"));

                    privateLeaves.add(new LeafPrivateInfo(
                            new LeafIndex(index),
                            encryption_priv,
                            signature_priv,
                            (List<PathSecretInfo>) plPathSecrets.clone()));

                    updatePaths.clear();
                    plPathSecrets.clear();
                    bufleaf.clear();
                }
                if (bufPaths.size() > 0 && !prevReading.equals("update_paths"))
                {

                    int sender = Integer.parseInt(bufPaths.get("sender"));
                    byte[] update_path = Hex.decode(bufPaths.get("update_path"));
                    byte[] commit_secret = Hex.decode(bufPaths.get("commit_secret"));
                    byte[] tree_hash_after = Hex.decode(bufPaths.get("tree_hash_after"));

                    updatePaths.add(new UpdatePathInfo(
                            new LeafIndex(sender),
                            (UpdatePath) MLSInputStream.decode(update_path, UpdatePath.class),
                            (List<PathSecret>) upPathSecrets.clone(),
                            commit_secret,
                            tree_hash_after
                    ));

                    upPathSecrets.clear();
                    bufPaths.clear();
                }
            }
            else if (reading.equals("path_secrets") && prevReading.equals("update_paths"))
            {
                if (line.equals("None"))
                {
                    upPathSecrets.add(new PathSecret(new byte[0]));
                }
                else
                {
                    upPathSecrets.add(new PathSecret(Hex.decode(line.trim())));
                }
            }

            int a = line.indexOf("=");
            if (a > -1)
            {
                if (reading.equals(""))
                {
                    buf.put(line.substring(0, a).trim(), line.substring(a + 1).trim());
                }
                else if (reading.equals("leaves_private"))
                {
                    bufleaf.put(line.substring(0, a).trim(), line.substring(a + 1).trim());
                }
                else if (reading.equals("update_paths"))
                {
                    bufPaths.put(line.substring(0, a).trim(), line.substring(a + 1).trim());
                }
                else if (reading.equals("path_secrets") && prevReading.equals("leaves_private"))
                {
                    int node = Integer.parseInt(line.substring(a + 1).trim());
                    line = bin.readLine();
                    line = line.trim();
                    a = line.indexOf("=");
                    byte[] pathsecret = Hex.decode(line.substring(a + 1).trim());
                    plPathSecrets.add(new PathSecretInfo(new NodeIndex(node), pathsecret));
                }
            }
        }
    }

    public void testMessages() throws Exception
    {
        InputStream src = TestResourceFinder.findTestResource("mls/testVectors/", "messages.txt");
        BufferedReader bin = new BufferedReader(new InputStreamReader(src));
        String line;
        HashMap<String, String> buf = new HashMap<String, String>();
        int count = 0;

        while((line = bin.readLine())!= null)
        {
            line = line.trim();
            if (line.length() == 0)
            {
                if (buf.size() > 0)
                {

                    System.out.println("test case: " + count);
                    byte[] mls_welcome = Hex.decode(buf.get("mls_welcome"));
                    byte[] mls_group_info = Hex.decode(buf.get("mls_group_info"));
                    byte[] mls_key_package = Hex.decode(buf.get("mls_key_package"));
                    byte[] ratchet_tree = Hex.decode(buf.get("ratchet_tree"));
                    byte[] group_secrets = Hex.decode(buf.get("group_secrets"));
                    byte[] add_proposal = Hex.decode(buf.get("add_proposal"));
                    byte[] update_proposal = Hex.decode(buf.get("update_proposal"));
                    byte[] remove_proposal = Hex.decode(buf.get("remove_proposal"));
                    byte[] pre_shared_key_proposal = Hex.decode(buf.get("pre_shared_key_proposal"));
                    byte[] re_init_proposal = Hex.decode(buf.get("re_init_proposal"));
                    byte[] external_init_proposal = Hex.decode(buf.get("external_init_proposal"));
                    byte[] group_context_extensions_proposal = Hex.decode(buf.get("group_context_extensions_proposal"));
                    byte[] commit = Hex.decode(buf.get("commit"));
                    byte[] public_message_application = Hex.decode(buf.get("public_message_application"));
                    byte[] public_message_proposal = Hex.decode(buf.get("public_message_proposal"));
                    byte[] public_message_commit = Hex.decode(buf.get("public_message_commit"));
                    byte[] private_message = Hex.decode(buf.get("private_message"));

                    MLSMessage mlsWelcome = (MLSMessage) MLSInputStream.decode(mls_welcome, MLSMessage.class);
                    byte[] mlsWelcomeBytes = MLSOutputStream.encode(mlsWelcome);
                    assertTrue(Arrays.areEqual(mlsWelcomeBytes, mls_welcome));

                    MLSMessage mlsGroupInfo = (MLSMessage) MLSInputStream.decode(mls_group_info, MLSMessage.class);
                    byte[] mlsGroupInfoBytes = MLSOutputStream.encode(mlsGroupInfo);
                    assertTrue(Arrays.areEqual(mlsGroupInfoBytes, mls_group_info));

                    MLSMessage mlsKeyPackage = (MLSMessage) MLSInputStream.decode(mls_key_package, MLSMessage.class );
                    byte[] mlsKeyPackageBytes = MLSOutputStream.encode(mlsKeyPackage);
                    assertTrue(Arrays.areEqual(mlsKeyPackageBytes, mls_key_package));

                    TreeKEMPublicKey ratchetTree = (TreeKEMPublicKey) MLSInputStream.decode(ratchet_tree, TreeKEMPublicKey.class);
                    byte[] ratchetTreeBytes = MLSOutputStream.encode(ratchetTree);
                    assertTrue(Arrays.areEqual(ratchetTreeBytes, ratchet_tree));

                    GroupSecrets groupSecrets = (GroupSecrets) MLSInputStream.decode(group_secrets, GroupSecrets.class );
                    byte[] groupSecretsBytes = MLSOutputStream.encode(groupSecrets);
                    assertTrue(Arrays.areEqual(groupSecretsBytes, group_secrets));

                    Proposal.Add addProposal = (Proposal.Add) MLSInputStream.decode(add_proposal, Proposal.Add.class);
                    byte[] addProposalBytes = MLSOutputStream.encode(addProposal);
                    assertTrue(Arrays.areEqual(addProposalBytes, add_proposal));

                    Proposal.Update updateProposal = (Proposal.Update) MLSInputStream.decode(update_proposal, Proposal.Update.class );
                    byte[] updateProposalBytes = MLSOutputStream.encode(updateProposal);
                    assertTrue(Arrays.areEqual(updateProposalBytes, update_proposal));

                    Proposal.Remove removeProposal = (Proposal.Remove) MLSInputStream.decode(remove_proposal, Proposal.Remove.class);
                    byte[] removeProposalBytes = MLSOutputStream.encode(removeProposal);
                    assertTrue(Arrays.areEqual(removeProposalBytes, remove_proposal));

                    Proposal.PreSharedKey preSharedKeyProposal = (Proposal.PreSharedKey) MLSInputStream.decode(pre_shared_key_proposal, Proposal.PreSharedKey.class);
                    byte[] preSharedKeyProposalBytes = MLSOutputStream.encode(preSharedKeyProposal);
                    assertTrue(Arrays.areEqual(preSharedKeyProposalBytes, pre_shared_key_proposal));

                    Proposal.ReInit reInitProposal = (Proposal.ReInit) MLSInputStream.decode(re_init_proposal, Proposal.ReInit.class);
                    byte[] reInitProposalBytes = MLSOutputStream.encode(reInitProposal);
                    assertTrue(Arrays.areEqual(reInitProposalBytes, re_init_proposal));

                    Proposal.ExternalInit externalInitProposal = (Proposal.ExternalInit) MLSInputStream.decode(external_init_proposal, Proposal.ExternalInit.class);
                    byte[] externalInitProposalBytes = MLSOutputStream.encode(externalInitProposal);
                    assertTrue(Arrays.areEqual(externalInitProposalBytes, external_init_proposal));

                    Proposal.GroupContextExtensions groupContextExtensionsProposal = (Proposal.GroupContextExtensions) MLSInputStream.decode(group_context_extensions_proposal, Proposal.GroupContextExtensions.class);
                    byte[] groupContextExtensionsProposalBytes = MLSOutputStream.encode(groupContextExtensionsProposal);
                    assertTrue(Arrays.areEqual(groupContextExtensionsProposalBytes, group_context_extensions_proposal));

                    Commit commitObj = (Commit) MLSInputStream.decode(commit, Commit.class);
                    byte[] commitBytes = MLSOutputStream.encode(commitObj);
                    assertTrue(Arrays.areEqual(commitBytes, commit));

                    MLSMessage publicMessageApplication = (MLSMessage) MLSInputStream.decode(public_message_application, MLSMessage.class);
                    byte[] publicMessageApplicationBytes = MLSOutputStream.encode(publicMessageApplication);
                    assertTrue(Arrays.areEqual(publicMessageApplicationBytes, public_message_application));

                    MLSMessage publicMessageProposal = (MLSMessage) MLSInputStream.decode(public_message_proposal, MLSMessage.class);
                    byte[] publicMessageProposalBytes = MLSOutputStream.encode(publicMessageProposal);
                    assertTrue(Arrays.areEqual(publicMessageProposalBytes, public_message_proposal));

                    MLSMessage publicMessageCommit = (MLSMessage) MLSInputStream.decode(public_message_commit, MLSMessage.class);
                    byte[] publicMessageCommitBytes = MLSOutputStream.encode(publicMessageCommit);
                    assertTrue(Arrays.areEqual(publicMessageCommitBytes, public_message_commit));

                    MLSMessage privateMessage = (MLSMessage) MLSInputStream.decode(private_message, MLSMessage.class);
                    byte[] privateMessageBytes = MLSOutputStream.encode(privateMessage);
                    assertTrue(Arrays.areEqual(privateMessageBytes, private_message));


                    count++;
                }
            }
            int a = line.indexOf("=");
            if (a > -1)
            {
                buf.put(line.substring(0, a).trim(), line.substring(a + 1).trim());
            }
        }
    }

}
