pragma solidity ^0.8.0;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract Signer {
    using ECDSA for bytes32;




    // stored nonces
    mapping(address => uint256) nonces;



    function recoverSigner(bytes32 data, bytes memory signature) public pure returns (address) {
        return data.recover(signature);
    }



    function getMessageHash(address _to, uint256 _amount, string memory _message, uint256 nonce) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(_to, _amount, _message, nonce));
    }



    function getEthSignedMessageHash(bytes32 _messageHash) public pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", _messageHash));
    }




    function verify(address _signer, address _to, uint256 _amount, string memory _message, uint256 nonce, bytes memory signature) public returns (bool) {
        bytes32 messageHash = getMessageHash(_to, _amount, _message, nonce);

        bytes32 ethSignedMessageHash = getEthSignedMessageHash(messageHash);

        address actualSigner = recoverSigner(ethSignedMessageHash, signature);

        require(nonces[actualSigner] == nonce - 1, "VerifySig fail");
        nonces[actualSigner] = nonce;

        return actualSigner == _signer;
    }


    function sendEthWithValidSig(address signer, address to, uint256 amount, string memory message, uint256 nonce, bytes memory signature) public {
        require(verify(signer, to, amount, message, nonce, signature), "InvalidSig");

        (bool success, ) = to.call{value: amount}("");
        require(success, "call failure");
    }
}