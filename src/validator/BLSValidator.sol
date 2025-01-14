// SPDX-License-Identifier: MIT

pragma solidity >=0.8.4 <0.9.0;

import "src/interfaces/IValidator.sol";
import "openzeppelin-contracts/contracts/utils/cryptography/EIP712.sol";
import "src/utils/KernelHelper.sol";
import "account-abstraction/samples/bls/lib/hubble-contracts/contracts/libs/BLS.sol";

contract BLSValidator is IKernelValidator {
    bytes32 public constant BLS_DOMAIN = keccak256("eip4337.bls.domain");
    
    event OwnerChanged(address indexed kernel, uint256[4] indexed oldPublicKey, uint256[4] indexed newPublicKey);

    mapping(address => uint256[4]) public blsValidatorStorage;

    function disable(bytes calldata) external payable override {
        delete blsValidatorStorage[msg.sender];
    }

    function enable(bytes calldata _data) external payable override {
        require(_data.length >= 128, "Calldata is not long enough for bls public key");

        uint256[4] memory publicKey = abi.decode(_data, (uint256[4]));
        uint256[4] memory oldPublicKey = blsValidatorStorage[msg.sender];
        blsValidatorStorage[msg.sender] = publicKey;

        emit OwnerChanged(msg.sender, oldPublicKey, publicKey);
    }

    function validateUserOp(UserOperation calldata _userOp, bytes32 _userOpHash, uint256)
        external
        payable
        override
        returns (ValidationData validationData)
    {
        uint256[4] memory publicKey = blsValidatorStorage[_userOp.sender];
        bytes memory hashBytes = abi.encodePacked(_userOpHash);

        uint256[2] memory message = BLS.hashToPoint(
            BLS_DOMAIN,
            hashBytes
        );
        uint256[2] memory decodedSignature = abi.decode(_userOp.signature, (uint256[2]));
        (bool verified, bool callSuccess) = BLS.verifySingle(decodedSignature, publicKey, message);

        if (verified && callSuccess) {
            return ValidationData.wrap(0);
        }
        // TODO: check if wallet recovered
        return SIG_VALIDATION_FAILED;
    }


    function validateSignature(bytes32 hash, bytes calldata signature) public view override returns (ValidationData) {
        uint256[4] memory publicKey = blsValidatorStorage[msg.sender];
        uint256[2] memory decodedSignature = abi.decode(signature, (uint256[2]));

        bytes memory hashBytes = abi.encodePacked(hash);
        uint256[2] memory message = BLS.hashToPoint(
            BLS_DOMAIN,
            hashBytes
        );
        (bool verified, bool callSuccess) = BLS.verifySingle(decodedSignature, publicKey, message);

        if (verified && callSuccess) {
            return ValidationData.wrap(0);
        }
        // TODO: check if wallet recovered
        return SIG_VALIDATION_FAILED;
    }

    function validCaller(address _caller, bytes calldata) external view override returns (bool) {
        return false;
    }
}
