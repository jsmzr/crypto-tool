# crypto-tool
![Build](https://github.com/jsmzr/crypto-tool/workflows/Build/badge.svg)
[![Version](https://img.shields.io/jetbrains/plugin/v/18363-crypto-tool.svg)](https://plugins.jetbrains.com/plugin/18363-crypto-tool)
[![Downloads](https://img.shields.io/jetbrains/plugin/d/18363-crypto-tool.svg)](https://plugins.jetbrains.com/plugin/18363-crypto-tool)

This is an encryption tool that provides Hash, Mac, Symmetric, Asymmetric and Signature algorithm support.

## ToDo
- [x] Create a new [IntelliJ Platform Plugin Template][template] project.
- [x] Get familiar with the [template documentation][template].
- [x] Verify the [pluginGroup](/gradle.properties), [plugin ID](/src/main/resources/META-INF/plugin.xml)
  and [sources package](/src/main/kotlin).
- [x] Review the [Legal Agreements](https://plugins.jetbrains.com/docs/marketplace/legal-agreements.html).
- [x] [Publish a plugin manually](https://plugins.jetbrains.com/docs/intellij/publishing-plugin.html?from=IJPluginTemplate)
  for the first time.
- [x] Set the Plugin ID in the above README badges.
- [x] Set the [Deployment Token](https://plugins.jetbrains.com/docs/marketplace/plugin-upload.html).
- [x] Click the <kbd>Watch</kbd> button on the top of the [IntelliJ Platform Plugin Template][template] to be notified
  about releases containing new features and fixes.

<!-- Plugin description -->
This is an encryption tool that provides Hash, Mac, Symmetric, Asymmetric and Signature algorithm support.

- Hash
  - SHA1
  - SHA2
  - SHA3
  - MD5, MD2
  - RipeMD
- Mac
  - HmacSHA1
  - HmacSHA2
  - HmacMD5
- Symmetric
  - AES
  - DES
  - 3DES
- Asymmetric
  - RSA
- Signature
  - SHA1withRSA, SHA2withRSA
  - SHA1withDSA, SHA2withDSA
  - SHA1withECDSA, SHA2withECDSA
  - MD5withRSA, MD2withRSA
- Google Tink
  - Aead(Authenticated Encryption with Associated Data)
  - Daead(Deterministic Authenticated Encryption with Associated Data)
  - Mac(Message Authentication Codes)
  - Signature
  - Hybrid
<!-- Plugin description end -->

## Installation

- Using IDE built-in plugin system:
  
  <kbd>Settings/Preferences</kbd> > <kbd>Plugins</kbd> > <kbd>Marketplace</kbd> > <kbd>Search for "crypto-tool"</kbd> >
  <kbd>Install Plugin</kbd>
  
- Manually:

  Download the [latest release](https://github.com/jsmzr/crypto-tool/releases/latest) and install it manually using
  <kbd>Settings/Preferences</kbd> > <kbd>Plugins</kbd> > <kbd>??????</kbd> > <kbd>Install plugin from disk...</kbd>


---
Plugin based on the [IntelliJ Platform Plugin Template][template].

[template]: https://github.com/JetBrains/intellij-platform-plugin-template
