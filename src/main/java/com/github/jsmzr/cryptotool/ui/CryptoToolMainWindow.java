package com.github.jsmzr.cryptotool.ui;

import com.github.jsmzr.cryptotool.constants.*;
import com.github.jsmzr.cryptotool.model.SignatureInfo;
import com.github.jsmzr.cryptotool.model.SymmetricInfo;
import com.github.jsmzr.cryptotool.tink.ByteArrayWriter;
import com.github.jsmzr.cryptotool.util.*;
import com.google.crypto.tink.CleartextKeysetHandle;
import com.google.crypto.tink.KeyTemplates;
import com.google.crypto.tink.KeysetHandle;
import com.intellij.icons.AllIcons;
import com.intellij.notification.NotificationGroupManager;
import com.intellij.notification.NotificationType;
import com.intellij.openapi.project.Project;

import javax.swing.*;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.util.Arrays;
import java.util.List;
import java.util.stream.IntStream;

public class CryptoToolMainWindow {
    private JPanel root;
    private JTabbedPane leftTabs;
    private JTabbedPane centerTabs;
    private JTabbedPane rightTabs;
    private JTextArea leftUtf8Text;
    private JTextArea rightUtf8Text;
    private JTextArea leftHexText;
    private JTextArea leftBase64Text;
    private JComboBox<String> hashComboBox;
    private JButton encodeButton;
    private JTextArea rightBase64Text;
    private JTextArea rightHexText;
    private JComboBox<String> macComboBox;
    private JTextField macKeyText;
    private JButton macButton;
    private JComboBox<SymmetricInfo> symmetricComboBox;
    private JTextField symmetricKeyText;
    private JTextField symmetricIvText;
    private JButton symmetricDecryptButton;
    private JButton symmetricEncryptButton;
    private JComboBox<Integer> tLenComboBox;
    private JPanel gcmPanel;
    private JPanel ivPanel;
    private JComboBox<String> asymmetricComboBox;
    private JTextField asymmetricPublicText;
    private JTextField asymmetricPrivateText;
    private JButton asymmetricKeyGenerateButton;
    private JButton asymmetricDecryptButton;
    private JButton asymmetricEncryptButton;
    private JComboBox<Integer> asymmetricKeyComboBox;
    private JComboBox<SignatureInfo> signatureComboBox;
    private JTextField signaturePublicText;
    private JTextField signaturePrivateText;
    private JComboBox<Integer> rsaKeyLengthComboBox;
    private JButton rsaKeyGenerateButton;
    private JButton signatureSignButton;
    private JButton signatureVerifyButton;
    private JPanel rsaKeyGeneratorPanel;
    private JPanel ecKeyGeneratorPanel;
    private JPanel dsaKeyGeneratorPanel;
    private JComboBox<Integer> ecKeyLengthComboBox;
    private JButton ecKeyGenerateButton;
    private JComboBox<Integer> dsaKeyLengthComboBox;
    private JButton dsaKeyGenerateButton;
    private JLabel verifyResultLabel;
    private JTabbedPane tinkTabs;
    private JComboBox tinkAeadComboBox;
    private JTextField tinkAeadKeyText;
    private JButton tinkAeadDecryptButton;
    private JButton tinkAeadEncryptButton;
    private JComboBox tinkDaeadComboBox;
    private JButton tinkDaeadDecryptButton;
    private JButton tinkDaeadEncryptButton;
    private JTextField tinkDaeadKeyText;
    private JButton tinkAeadKeyGenerateButton;
    private JButton tinkDaeadKeyGenerateButton;
    private JComboBox tinkMacComboBox;
    private JTextField tinkMacKeyText;
    private JButton tinkMacKeyGenerateButton;
    private JLabel tinkMacVerifyResultLabel;
    private JButton tinkSignatureKeyGeneratePairButton;
    private JButton tinkMacButton;
    private JButton tinkMacVerifyButton;
    private JComboBox tinkSignatureComboBox;
    private JTextField tinkSignaturePrivateKeyText;
    private JTextField tinkSignaturePublicKeyText;
    private JButton tinkSignatureButton;
    private JButton tinkSignatureVerifyButton;
    private JLabel tinkSignatureVerifyResultLabel;
    private JComboBox tinkHybridComboBox;
    private JTextField tinkHybridPrivateKeyText;
    private JTextField tinkHybridPublicKeyText;
    private JButton tinkHybridKeyGenerateButton;
    private JButton tinkHybridDecryptButton;
    private JButton tinkHybridEncryptButton;
    private JTextField tinkAeadAssociatedText;
    private JTextField tinkHybridContextText;
    private JTextField tinkDaeadAssociatedText;

    private static final int[] tLenArr = {96, 104, 112, 120, 128};
    private static final int[] rsaKeyLength = {512, 1024, 2048, 4096};
    private static final int[] ecKeyLength = {112, 256, 512, 571};
    private static final int[] dsaKeyLength = IntStream.range(512, 1025).filter(o -> o % 64 == 0).toArray();
    private int leftTabIndex = 0;
    private int rightTabIndex = 0;
    private byte[] leftContent;
    private byte[] rightContent;
    private final Project project;

    public CryptoToolMainWindow(Project project) {
        this.project = project;
        initTabs();
        initHash();
        initMac();
        initSymmetric();
        initAsymmetric();
        initSignature();
        initTink();
    }

    public JPanel getRoot() {
        return root;
    }

    private void initTabs() {
        leftTabs.addChangeListener(e -> {
            int index = leftTabs.getSelectedIndex();
            if (index != leftTabIndex) {
                updateLeftContent(leftTabIndex);
                leftTabIndex = index;
            }
            showLeftContent();
        });

        rightTabs.addChangeListener(e -> {
            int index = rightTabs.getSelectedIndex();
            if (index != rightTabIndex) {
                updateRightContent(rightTabIndex);
                rightTabIndex = index;
            }
            showRightContent();
        });
        centerTabs.addChangeListener(e -> {
            // If you have selected Signature, then the right side will not be available.
            resetRightTabs();
            verifyResultLabel.setVisible(false);
        });
        // default select hex
        rightTabs.setSelectedIndex(1);
    }

    private void initHash() {
        for (HashType value : HashType.values()) {
            hashComboBox.addItem(value.getValue());
        }
        encodeButton.addActionListener(e -> {
            String alg = (String) hashComboBox.getSelectedItem();
            updateLeftContent();
            try {
                if (alg.startsWith("Ripe")) {
                    rightContent = HashUtil.hashByRipeMD(alg, leftContent);
                } else {
                    rightContent = HashUtil.hash(alg, leftContent);
                }
            } catch (Exception exception) {
                notify(exception.getMessage());
                return;
            }
            showRightContent();
        });
    }

    private void initMac() {
        for (MacType value : MacType.values()) {
            macComboBox.addItem(value.getValue());
        }
        macButton.addActionListener(e -> {
            String alg = (String) macComboBox.getSelectedItem();
            updateLeftContent();
            try {
                rightContent = MacUtil.mac(alg, EncodeUtil.base64ToBytes(macKeyText.getText()), leftContent);
            } catch (Exception exception) {
                notify(exception.getMessage());
                return;
            }
            showRightContent();
        });
    }

    private void initSymmetric() {
        for (SymmetricType value : SymmetricType.values()) {
            symmetricComboBox.addItem(new SymmetricInfo(value.getValue()));
        }
        for (int tLen : tLenArr) {
            tLenComboBox.addItem(tLen);
        }
        symmetricComboBox.addActionListener(e -> {
            SymmetricInfo info = (SymmetricInfo) symmetricComboBox.getSelectedItem();
            String mode = info.getMode();
            gcmPanel.setVisible("GCM".equals(mode));
            ivPanel.setVisible(!"ECB".equals(mode));
        });
        symmetricEncryptButton.addActionListener(e -> {
            updateLeftContent();
            SymmetricInfo info = (SymmetricInfo) symmetricComboBox.getSelectedItem();
            try {
                byte[] key = EncodeUtil.base64ToBytes(symmetricKeyText.getText());
                byte[] iv = EncodeUtil.base64ToBytes(symmetricIvText.getText());
                int tLen = (int) tLenComboBox.getSelectedItem();
                rightContent = SymmetricUtil.encrypt(info, key, leftContent, iv, tLen);
            } catch (Exception exception) {
                notify(exception.getMessage());
                return;
            }
            showRightContent();
        });

        symmetricDecryptButton.addActionListener(e -> {
            updateRightContent();
            SymmetricInfo info = (SymmetricInfo) symmetricComboBox.getSelectedItem();
            try {
                byte[] key = EncodeUtil.base64ToBytes(symmetricKeyText.getText());
                byte[] iv = EncodeUtil.base64ToBytes(symmetricIvText.getText());
                int tLen = (int) tLenComboBox.getSelectedItem();
                leftContent = SymmetricUtil.decrypt(info, key, rightContent, iv, tLen);
            } catch (Exception exception) {
                notify(exception.getMessage());
                return;
            }
            showLeftContent();
        });
    }

    private void initAsymmetric() {
        for (AsymmetricType value : AsymmetricType.values()) {
            asymmetricComboBox.addItem(value.getValue());
        }
        for (int keyLength : rsaKeyLength) {
            asymmetricKeyComboBox.addItem(keyLength);
        }
        asymmetricEncryptButton.addActionListener(e -> {
            updateLeftContent();
            String alg = (String) asymmetricComboBox.getSelectedItem();
            try {
                byte[] pubKey = EncodeUtil.base64ToBytes(asymmetricPublicText.getText());
                rightContent = AsymmetricUtil.encrypt(alg, pubKey, leftContent);
            } catch (Exception exception) {
                notify(exception.getMessage());
                return;
            }
            showRightContent();
        });

        asymmetricDecryptButton.addActionListener(e -> {
            updateRightContent();
            String alg = (String) asymmetricComboBox.getSelectedItem();
            try {
                byte[] priKey = EncodeUtil.base64ToBytes(asymmetricPrivateText.getText());
                leftContent = AsymmetricUtil.decrypt(alg, priKey, rightContent);
            } catch (Exception exception) {
                notify(exception.getMessage());
                return;
            }
            showLeftContent();
        });

        asymmetricKeyGenerateButton.addActionListener(e -> {
            String alg = (String) asymmetricComboBox.getSelectedItem();
            int keyLength = (int) asymmetricKeyComboBox.getSelectedItem();

            KeyPair keyPair;
            try {
                keyPair = AsymmetricUtil.generateKey(alg, keyLength);
            } catch (Exception exception) {
                notify(exception.getMessage());
                return;
            }
            asymmetricPublicText.setText(EncodeUtil.bytesToBase64(keyPair.getPublic().getEncoded()));
            asymmetricPrivateText.setText(EncodeUtil.bytesToBase64(keyPair.getPrivate().getEncoded()));
        });
    }

    private void initSignature() {
        for (SignatureType value : SignatureType.values()) {
            signatureComboBox.addItem(new SignatureInfo(value.getValue()));
        }
        for (int i : rsaKeyLength) {
            rsaKeyLengthComboBox.addItem(i);
        }
        for (int i : ecKeyLength) {
            ecKeyLengthComboBox.addItem(i);
        }
        for (int i : dsaKeyLength) {
            dsaKeyLengthComboBox.addItem(i);
        }
        signatureSignButton.addActionListener(e -> {
            updateLeftContent();
            SignatureInfo info = (SignatureInfo) signatureComboBox.getSelectedItem();
            try {
                byte[] priKey = EncodeUtil.base64ToBytes(signaturePrivateText.getText());
                rightContent = SignatureUtil.sign(info, priKey, leftContent);
            } catch (Exception exception) {
                notify(exception.getMessage());
                return;
            }
            showRightContent();
        });
        signatureVerifyButton.addActionListener(e -> {
            updateLeftContent();
            SignatureInfo info = (SignatureInfo) signatureComboBox.getSelectedItem();
            boolean verifyResult;
            try {
                byte[] pubKey = EncodeUtil.base64ToBytes(signaturePublicText.getText());
                verifyResult = SignatureUtil.verify(info, pubKey, leftContent, rightContent);
            } catch (Exception exception) {
                notify(exception.getMessage());
                return;
            }
            if (verifyResult) {
                verifyResultLabel.setIcon(AllIcons.General.InspectionsOK);
            } else {
                verifyResultLabel.setIcon(AllIcons.CodeWithMe.CwmTerminate);
            }
            verifyResultLabel.setVisible(true);
        });
        signatureComboBox.addActionListener(e -> {
            SignatureInfo info = (SignatureInfo) signatureComboBox.getSelectedItem();
            String keyType = info.getKey();
            switch (keyType) {
                case "RSA":
                    rsaKeyGeneratorPanel.setVisible(true);
                    ecKeyGeneratorPanel.setVisible(false);
                    dsaKeyGeneratorPanel.setVisible(false);
                    break;
                case "EC":
                    rsaKeyGeneratorPanel.setVisible(false);
                    ecKeyGeneratorPanel.setVisible(true);
                    dsaKeyGeneratorPanel.setVisible(false);
                    break;
                case "DSA":
                    rsaKeyGeneratorPanel.setVisible(false);
                    ecKeyGeneratorPanel.setVisible(false);
                    dsaKeyGeneratorPanel.setVisible(true);
                    break;
            }
            signaturePrivateText.setText("");
            signaturePublicText.setText("");
            verifyResultLabel.setVisible(false);
        });

        rsaKeyGenerateButton.addActionListener(e -> {
            int keyLength = (int) rsaKeyLengthComboBox.getSelectedItem();
            updateSignatureKey("RSA", keyLength);
        });
        ecKeyGenerateButton.addActionListener(e -> {
            int keyLength = (int) ecKeyLengthComboBox.getSelectedItem();
            updateSignatureKey("EC", keyLength);
        });
        dsaKeyGenerateButton.addActionListener(e -> {
            int keyLength = (int) dsaKeyLengthComboBox.getSelectedItem();
            updateSignatureKey("DSA", keyLength);
        });

    }

    private void initTink() {
        tinkTabs.addChangeListener(e -> {
            int current = tinkTabs.getSelectedIndex();
            resetRightTabs();
            tinkSignatureVerifyResultLabel.setVisible(false);
            tinkMacVerifyResultLabel.setVisible(false);
        });
        initTinkAead();
        initTinkDaead();
        initTinkMac();
        initTinkSignature();
        initTinkHybrid();
    }

    private void initTinkAead() {
        for (TinkAeadType value : TinkAeadType.values()) {
            tinkAeadComboBox.addItem(value.name());
        }
        tinkAeadComboBox.addPropertyChangeListener(e -> {
            tinkAeadKeyText.setText("");
        });
        tinkAeadKeyGenerateButton.addActionListener(e -> {
            String alg = (String) tinkAeadComboBox.getSelectedItem();
            byte[] bytes = generateKey(alg);
            if (bytes == null) {
                return;
            }
            tinkAeadKeyText.setText(EncodeUtil.bytesToBase64(bytes));
        });
        tinkAeadEncryptButton.addActionListener(e -> {
            updateLeftContent();
            byte[] bytes = EncodeUtil.base64ToBytes(tinkAeadKeyText.getText());
            byte[] associated = EncodeUtil.base64ToBytes(tinkAeadAssociatedText.getText());
            rightContent = TinkAeadUtil.encrypt(leftContent, associated, bytes);
            showRightContent();
        });
        tinkAeadDecryptButton.addActionListener(e -> {
            updateRightContent();
            byte[] bytes = EncodeUtil.base64ToBytes(tinkAeadKeyText.getText());
            byte[] associated = EncodeUtil.base64ToBytes(tinkAeadAssociatedText.getText());
            leftContent = TinkAeadUtil.decrypt(rightContent, associated, bytes);
            showLeftContent();
        });
    }

    private void initTinkDaead() {
        for (TinkDaeadType value : TinkDaeadType.values()) {
            tinkDaeadComboBox.addItem(value.name());
        }
        tinkDaeadComboBox.addPropertyChangeListener(e -> {
            tinkDaeadKeyText.setText("");
        });
        tinkDaeadKeyGenerateButton.addActionListener(e -> {
            String alg = (String) tinkDaeadComboBox.getSelectedItem();
            byte[] bytes = generateKey(alg);
            if (bytes == null) {
                return;
            }
            tinkDaeadKeyText.setText(EncodeUtil.bytesToBase64(bytes));
        });
        tinkDaeadEncryptButton.addActionListener(e -> {
            updateLeftContent();
            byte[] bytes = EncodeUtil.base64ToBytes(tinkDaeadKeyText.getText());
            byte[] associated = EncodeUtil.base64ToBytes(tinkDaeadAssociatedText.getText());
            rightContent = TinkDaeadUtil.encrypt(leftContent, associated, bytes);
            showRightContent();
        });
        tinkDaeadDecryptButton.addActionListener(e -> {
            updateRightContent();
            byte[] bytes = EncodeUtil.base64ToBytes(tinkDaeadKeyText.getText());
            byte[] associated = EncodeUtil.base64ToBytes(tinkDaeadAssociatedText.getText());
            leftContent = TinkDaeadUtil.decrypt(rightContent, associated, bytes);
            showLeftContent();
        });
    }

    private void initTinkMac() {
        for (TinkMacType value : TinkMacType.values()) {
            tinkMacComboBox.addItem(value.name());
        }
        tinkMacComboBox.addPropertyChangeListener(e -> {
            tinkMacVerifyResultLabel.setVisible(false);
            tinkMacKeyText.setText("");
        });
        tinkMacKeyGenerateButton.addActionListener(e -> {
            String alg = (String) tinkMacComboBox.getSelectedItem();
            byte[] bytes = generateKey(alg);
            if (bytes == null) {
                return;
            }
            tinkMacKeyText.setText(EncodeUtil.bytesToBase64(bytes));
        });
        tinkMacButton.addActionListener(e -> {
            updateLeftContent();
            rightContent = TinkMacUtil.mac(leftContent, EncodeUtil.base64ToBytes(tinkMacKeyText.getText()));
            showRightContent();
        });
        tinkMacVerifyButton.addActionListener(e -> {
            updateLeftContent();
            updateRightContent();
            byte[] bytes = EncodeUtil.base64ToBytes(tinkMacKeyText.getText());
            try {
                TinkMacUtil.verify(leftContent, bytes, rightContent);
                tinkMacVerifyResultLabel.setIcon(AllIcons.General.InspectionsOK);
            } catch (Exception exception) {
                tinkMacVerifyResultLabel.setIcon(AllIcons.CodeWithMe.CwmTerminate);
                notify(exception.getMessage());
            }
            tinkMacVerifyResultLabel.setVisible(true);
        });
    }

    private void initTinkSignature() {
        for (TinkSignatureType value : TinkSignatureType.values()) {
            tinkSignatureComboBox.addItem(value.name());
        }
        tinkSignatureComboBox.addPropertyChangeListener(e -> {
            tinkSignatureVerifyResultLabel.setVisible(false);
            tinkSignaturePrivateKeyText.setText("");
            tinkSignaturePublicKeyText.setText("");
        });
        tinkSignatureKeyGeneratePairButton.addActionListener(e -> {
            String alg = (String) tinkSignatureComboBox.getSelectedItem();
            List<byte[]> keyPair = generateKeyPair(alg);
            if (keyPair == null || keyPair.size() != 2) {
                return;
            }
            tinkSignaturePrivateKeyText.setText(EncodeUtil.bytesToBase64(keyPair.get(0)));
            tinkSignaturePublicKeyText.setText(EncodeUtil.bytesToBase64(keyPair.get(1)));
        });
        tinkSignatureButton.addActionListener(e -> {
            updateLeftContent();
            byte[] priKey = EncodeUtil.base64ToBytes(tinkSignaturePrivateKeyText.getText());
            rightContent = TinkSignatureUtil.sign(leftContent, priKey);
            showRightContent();
        });

        tinkSignatureVerifyButton.addActionListener(e -> {
            updateLeftContent();
            byte[] pubKey = EncodeUtil.base64ToBytes(tinkSignaturePublicKeyText.getText());
            try {
                TinkSignatureUtil.verify(leftContent, pubKey, rightContent);
                tinkSignatureVerifyResultLabel.setIcon(AllIcons.General.InspectionsOK);
            } catch (Exception ex) {
                tinkSignatureVerifyResultLabel.setIcon(AllIcons.CodeWithMe.CwmTerminate);
                notify(ex.getMessage());
            }
            tinkSignatureVerifyResultLabel.setVisible(true);
        });
    }

    private void initTinkHybrid() {
        for (TinkHybridType value : TinkHybridType.values()) {
            tinkHybridComboBox.addItem(value.name());
        }
        tinkHybridComboBox.addPropertyChangeListener(e -> {
            tinkHybridPublicKeyText.setText("");
            tinkHybridPrivateKeyText.setText("");
        });
        tinkHybridKeyGenerateButton.addActionListener(e -> {
            String alg = (String) tinkHybridComboBox.getSelectedItem();
            List<byte[]> keyPair = generateKeyPair(alg);
            if (keyPair == null || keyPair.size() != 2) {
                return;
            }
            tinkHybridPrivateKeyText.setText(EncodeUtil.bytesToBase64(keyPair.get(0)));
            tinkHybridPublicKeyText.setText(EncodeUtil.bytesToBase64(keyPair.get(1)));
        });
        tinkHybridEncryptButton.addActionListener(e -> {
            updateLeftContent();
            byte[] pubKey = EncodeUtil.base64ToBytes(tinkHybridPublicKeyText.getText());
            byte[] context = EncodeUtil.base64ToBytes(tinkHybridContextText.getText());
            rightContent = TinkHybridUtil.encrypt(leftContent, context, pubKey);
            showRightContent();
        });
        tinkHybridDecryptButton.addActionListener(e -> {
            updateRightContent();
            byte[] priKey = EncodeUtil.base64ToBytes(tinkHybridPrivateKeyText.getText());
            byte[] context = EncodeUtil.base64ToBytes(tinkHybridContextText.getText());
            leftContent = TinkHybridUtil.decrypt(rightContent, context, priKey);
            showLeftContent();
        });
    }

    private byte[] generateKey(String alg) {
        KeysetHandle keysetHandle;
        try {
            keysetHandle = KeysetHandle.generateNew(KeyTemplates.get(alg));
        } catch (GeneralSecurityException ex) {
            notify(ex.getMessage());
            return null;
        }
        ByteArrayWriter writer = new ByteArrayWriter();
        try {
            CleartextKeysetHandle.write(keysetHandle, writer);
        } catch (IOException ex) {
            notify(ex.getMessage());
            return null;
        }
        return writer.getByteArray();
    }

    private List<byte[]> generateKeyPair(String alg) {
        KeysetHandle keysetHandle;
        try {
            keysetHandle = KeysetHandle.generateNew(KeyTemplates.get(alg));
        } catch (GeneralSecurityException ex) {
            notify(ex.getMessage());
            return null;
        }
        ByteArrayWriter priWriter = new ByteArrayWriter();
        ByteArrayWriter pubWriter = new ByteArrayWriter();
        try {
            CleartextKeysetHandle.write(keysetHandle, priWriter);
            CleartextKeysetHandle.write(keysetHandle.getPublicKeysetHandle(), pubWriter);
        } catch (IOException | GeneralSecurityException e) {
            notify(e.getMessage());
            return null;
        }
        return Arrays.asList(priWriter.getByteArray(), pubWriter.getByteArray());
    }

    private void notify(String content) {
        NotificationGroupManager.getInstance().getNotificationGroup("CryptoTool")
                .createNotification(content, NotificationType.ERROR)
                .notify(project);
    }

    private void updateSignatureKey(String alg, int length) {
        KeyPair keyPair = AsymmetricUtil.generateKey(alg, length);
        signaturePublicText.setText(EncodeUtil.bytesToBase64(keyPair.getPublic().getEncoded()));
        signaturePrivateText.setText(EncodeUtil.bytesToBase64(keyPair.getPrivate().getEncoded()));
    }

    private void updateLeftContent() {
        int leftIndex = leftTabs.getSelectedIndex();
        updateLeftContent(leftIndex);
    }

    private void updateLeftContent(int leftIndex) {
        try {

            if (leftIndex == 0) {
                leftContent = leftUtf8Text.getText().getBytes(StandardCharsets.UTF_8);
            } else if (leftIndex == 1) {
                leftContent = EncodeUtil.hexStringToBytes(leftHexText.getText());
            } else {
                leftContent = EncodeUtil.base64ToBytes(leftBase64Text.getText());
            }
        } catch (Exception e) {
            notify(e.getMessage());
        }
    }

    private void updateRightContent() {
        int rightIndex = rightTabs.getSelectedIndex();
        updateRightContent(rightIndex);
    }

    private void updateRightContent(int rightIndex) {
        try {
            if (rightIndex == 0) {
                rightContent = rightUtf8Text.getText().getBytes(StandardCharsets.UTF_8);
            } else if (rightIndex == 1) {
                rightContent = EncodeUtil.hexStringToBytes(rightHexText.getText());
            } else {
                rightContent = EncodeUtil.base64ToBytes(rightBase64Text.getText());
            }
        } catch (Exception e) {
            notify(e.getMessage());
        }
    }

    private void showLeftContent() {
        if (leftContent == null) {
            leftUtf8Text.setText("");
            leftHexText.setText("");
            leftBase64Text.setText("");
            return;
        }
        int encodeIndex = leftTabs.getSelectedIndex();
        try {
            if (encodeIndex == 0) {
                leftUtf8Text.setText(new String(leftContent));
            } else if (encodeIndex == 1) {
                leftHexText.setText(EncodeUtil.bytesToHexString(leftContent));
            } else if (encodeIndex == 2) {
                leftBase64Text.setText(EncodeUtil.bytesToBase64(leftContent));
            }
        } catch (Exception e) {
            notify(e.getMessage());
        }
    }

    private void showRightContent() {
        if (rightContent == null) {
            rightUtf8Text.setText("");
            rightHexText.setText("");
            rightBase64Text.setText("");
            return;
        }
        int encodeIndex = rightTabs.getSelectedIndex();
        try {
            if (encodeIndex == 0) {
                rightUtf8Text.setText(new String(rightContent));
            } else if (encodeIndex == 1) {
                rightHexText.setText(EncodeUtil.bytesToHexString(rightContent));
            } else if (encodeIndex == 2) {
                rightBase64Text.setText(EncodeUtil.bytesToBase64(rightContent));
            }
        } catch (Exception e) {
            notify(e.getMessage());
        }
    }

    private void resetRightTabs() {
        rightUtf8Text.setText("");
        rightHexText.setText("");
        rightBase64Text.setText("");
    }
}
