// SPDX-License-Identifier: SEE LICENSE IN LICENSE
pragma solidity ^0.8.24;

interface IEigenLayerStrategy {
    function processOffChainComputation(bytes calldata _input) external view returns (bytes memory);
}
