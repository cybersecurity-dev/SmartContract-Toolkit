# Smart Contract Toolkit 
[![YouTube](https://img.shields.io/badge/YouTube-%23FF0000.svg?style=for-the-badge&logo=YouTube&logoColor=white)](https://youtube.com/playlist?list=PL9V4Zu3RroiVaXl6bMLFH2spgi7bzAOPV&si=XaZyQtmPQOJQ5IZs) [![Reddit](https://img.shields.io/badge/Reddit-FF4500?style=for-the-badge&logo=reddit&logoColor=white)](https://www.reddit.com/r/smartcontracts/)

<p align="center">
    <a href="https://github.com/cybersecurity-dev/"><img height="25" src="https://github.com/cybersecurity-dev/cybersecurity-dev/blob/main/assets/github.svg" alt="GitHub"></a>
    &nbsp;
    <a href="https://www.youtube.com/@CyberThreatDefence"><img height="25" src="https://github.com/cybersecurity-dev/cybersecurity-dev/blob/main/assets/youtube.svg" alt="YouTube"></a>
    &nbsp;
    <a href="https://cyberthreatdefence.com/my_awesome_lists"><img height="20" src="https://github.com/cybersecurity-dev/cybersecurity-dev/blob/main/assets/blog.svg" alt="My Awesome Lists"></a>
    <img src="https://github.com/cybersecurity-dev/cybersecurity-dev/blob/main/assets/bar.gif">
</p>

This repository focuses on the extraction of features from smart contract bytecode/source code for the purpose of vulnerability/malicious detection.

### SC Specialized Programming Languages
* [Clarity](https://clarity-lang.org/) - Clarity brings smart contracts to Bitcoin. It is a decidable language, meaning you can know, with certainty, from the code itself what the program will do. Clarity is interpreted (not compiled) & the source code is published on the blockchain. Clarity gives developers a safe way to build complex smart contracts for the world's most secure blockchain.
* [Solidity](https://soliditylang.org/) - A statically-typed curly-braces programming language designed for developing smart contracts that run on Ethereum.
* [Vyper](https://vyperlang.org/) - Vyper is a smart contract language with a relentless focus on security, simplicity, and readability. It empowers developers to write clean, auditable, and gas-efficient code for the EVM, without common pitfalls.

### Security Analysis Tools for SC
- [eThor](https://secpriv.wien/ethor/) - A sound static analyzer for EVM smart contracts based on HoRSt.
- [Mythril](https://github.com/ConsenSysDiligence/mythril) - Mythril is a symbolic-execution-based security analysis tool for EVM bytecode. It detects security vulnerabilities in smart contracts built for Ethereum and other EVM-compatible blockchains.
- [Securify v2.0](https://github.com/eth-sri/securify2) - Securify 2.0 is a security scanner for Ethereum smart contracts supported by the Ethereum Foundation and ChainSecurity.
- [Slither](https://github.com/crytic/slither) - Slither is a Solidity & Vyper static analysis framework written in Python3. It runs a suite of vulnerability detectors, prints visual information about contract details, and provides an API to easily write custom analyses. Slither enables developers to find vulnerabilities, enhance their code comprehension, and quickly prototype custom analyses.
- [SmartCheck](https://github.com/smartdec/smartcheck) - SmartCheck – a static analysis tool that detects vulnerabilities and bugs in Solidity programs (Ethereum-based smart contracts).
- [Solhint](https://github.com/protofire/solhint) - Solhint is an open-source project to provide a linting utility for Solidity code.
- [Osiris](https://github.com/christoftorres/Osiris) - An analysis tool to detect integer bugs in Ethereum smart contracts.
- [Oyente](https://github.com/enzymefinance/oyente) (_This project is not maintained anymore_) - An Analysis Tool for Smart Contracts

### References
- [An Ethereum Virtual Machine Opcodes Interactive Reference](https://www.evm.codes/)
- [Opcodes for the EVM](https://ethereum.org/en/developers/docs/evm/opcodes/)
- [Ethereum Virtual Machine Opcodes](https://ethervm.io/)

### SC Crawler
- [ChainWalker](https://github.com/0xsha/ChainWalker) - ChainWalker is a smart contract scraper which uses RCP/IPC calls to extract the information. A small tool that can help us find contracts, extract the EVM code, and disassemble the opcodes. It allows us to select specific blocks or even specific contract balances.
