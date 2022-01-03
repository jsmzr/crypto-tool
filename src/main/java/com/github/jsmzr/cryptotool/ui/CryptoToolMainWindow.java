package com.github.jsmzr.cryptotool.ui;

import com.github.jsmzr.cryptotool.constants.HashType;
import com.github.jsmzr.cryptotool.constants.MacType;
import com.github.jsmzr.cryptotool.constants.SymmetricType;
import com.github.jsmzr.cryptotool.model.SymmetricInfo;
import com.github.jsmzr.cryptotool.util.EncodeUtil;
import com.github.jsmzr.cryptotool.util.HashUtil;
import com.github.jsmzr.cryptotool.util.MacUtil;
import com.github.jsmzr.cryptotool.util.SymmetricUtil;
import com.intellij.notification.NotificationGroupManager;
import com.intellij.notification.NotificationType;
import com.intellij.openapi.project.Project;

import javax.swing.*;
import java.nio.charset.StandardCharsets;

public class CryptoToolMainWindow {
    private JPanel root;
    private JTabbedPane leftTabs;
    private JTabbedPane centerTabs;
    private JTabbedPane rightTabs;
    private JTextArea leftUtf8Text;
    private JTextArea rightUtf8Text;
    private JTextArea leftHexText;
    private JTextArea leftBase64Text;
    private JComboBox hashComboBox;
    private JButton encodeButton;
    private JTextArea rightBase64Text;
    private JTextArea rightHexText;
    private JComboBox macComboBox;
    private JTextField macKeyText;
    private JButton macButton;
    private JComboBox symmetricComboBox;
    private JTextField symmetricKeyText;
    private JTextField symmetricIvText;
    private JButton symmetricDecryptButton;
    private JButton symmetricEncryptButton;
    private JComboBox tLenComboBox;
    private JPanel gcmPanel;
    private JPanel ivPanel;

    private static final int[] tLenArr = {96, 104, 112, 120, 128};
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
                rightContent = MacUtil.mac(alg, EncodeUtil.hexStringToBytes(macKeyText.getText()), leftContent);
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
                byte[] key = EncodeUtil.hexStringToBytes(symmetricKeyText.getText());
                byte[] iv = EncodeUtil.hexStringToBytes(symmetricIvText.getText());
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
                byte[] key = EncodeUtil.hexStringToBytes(symmetricKeyText.getText());
                byte[] iv = EncodeUtil.hexStringToBytes(symmetricIvText.getText());
                int tLen = (int) tLenComboBox.getSelectedItem();
                leftContent = SymmetricUtil.decrypt(info, key, rightContent, iv, tLen);
            } catch (Exception exception) {
                notify(exception.getMessage());
                return;
            }
            showLeftContent();
        });
    }

    private void notify(String content) {
        NotificationGroupManager.getInstance().getNotificationGroup("CryptoTool")
                .createNotification(content, NotificationType.ERROR)
                .notify(project);
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
}
