// SPDX-License-Identifier: SEE LICENSE IN LICENSE
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {Hooks} from "v4-core/libraries/Hooks.sol";
import {IHooks} from "v4-core/interfaces/IHooks.sol";
import {TickMath} from "v4-core/libraries/TickMath.sol";
import {IPoolManager} from "v4-core/interfaces/IPoolManager.sol";
import {PoolKey} from "v4-core/types/PoolKey.sol";
import {BalanceDelta} from "v4-core/types/BalanceDelta.sol";
import {PoolId, PoolIdLibrary} from "v4-core/types/PoolId.sol";
import {CurrencyLibrary, Currency} from "v4-core/types/Currency.sol";
import {PoolSwapTest} from "@uniswap/v4-core/src/test/PoolSwapTest.sol";
import {RugGuard} from "src/RugGuard.sol";
import {PositionConfig} from "v4-periphery/src/libraries/PositionConfig.sol";
import {IPositionManager} from "v4-periphery/src/interfaces/IPositionManager.sol";
import {Fixtures} from "./utils/Fixtures.sol";
import {EasyPosm} from "./utils/EasyPosm.sol";
import {MockBrevisVerifier} from "./mocks/MockBrevisVerifier.sol";
import {MockEigenLayerStrategy} from "./mocks/MockEigenLayerStrategy.sol";
import {MockChainlinkAggregator} from "./mocks/MockChainlinkAggregator.sol";

/**
 * @title RugGuardTest
 * @notice Test contract for the RugGuard contract
 * @dev This contract contains unit tests for the RugGuard contract
 */
contract RugGuardTest is Test, Fixtures {
    using PoolIdLibrary for PoolKey;
    using CurrencyLibrary for Currency;
    using EasyPosm for IPositionManager;

    RugGuard hook;
    PoolId poolId;
    MockBrevisVerifier brevisVerifier;
    MockEigenLayerStrategy eigenLayerStrategy;
    MockChainlinkAggregator priceFeed0;
    MockChainlinkAggregator priceFeed1;
    uint256 initialTokenId;
    PositionConfig config;

    /**
     * @notice Emitted when liquidity changes in a pool
     * @param poolId The ID of the pool
     * @param liquidityDelta The change in liquidity
     * @param newTotalLiquidity The new total liquidity after the change
     */
    event LiquidityChanged(PoolId indexed poolId, int256 liquidityDelta, uint256 newTotalLiquidity);

    /**
     * @notice Emitted when the risk score of a pool is updated
     * @param poolId The ID of the pool
     * @param newRiskScore The new risk score
     */
    event RiskScoreUpdated(PoolId indexed poolId, uint256 newRiskScore);

    /**
     * @notice Emitted when the liquidity change threshold is updated
     * @param poolId The ID of the pool
     * @param newThreshold The new threshold value
     */
    event ThresholdUpdated(PoolId indexed poolId, uint256 newThreshold);

    /**
     * @notice Set up the test environment
     * @dev Deploys necessary contracts and initializes the test environment
     */
    function setUp() public {
        deployFreshManagerAndRouters();
        deployMintAndApprove2Currencies();
        deployAndApprovePosm(manager);

        eigenLayerStrategy = new MockEigenLayerStrategy();
        brevisVerifier = new MockBrevisVerifier();
        priceFeed0 = new MockChainlinkAggregator();
        priceFeed1 = new MockChainlinkAggregator();

        address flags = address(
            uint160(
                Hooks.AFTER_INITIALIZE_FLAG | Hooks.BEFORE_ADD_LIQUIDITY_FLAG | Hooks.BEFORE_REMOVE_LIQUIDITY_FLAG
                    | Hooks.BEFORE_SWAP_FLAG | Hooks.AFTER_SWAP_FLAG | Hooks.AFTER_REMOVE_LIQUIDITY_FLAG
                    | Hooks.AFTER_ADD_LIQUIDITY_FLAG
            )
        );

        bytes memory constructorArgs = abi.encode(manager, eigenLayerStrategy, brevisVerifier);
        deployCodeTo("RugGuard.sol:RugGuard", constructorArgs, flags);

        hook = RugGuard(payable(flags));

        key = PoolKey(currency0, currency1, 3000, 60, IHooks(hook));
        poolId = key.toId();
        manager.initialize(key, SQRT_PRICE_1_1, ZERO_BYTES);

        config = PositionConfig({
            poolKey: key,
            tickLower: TickMath.minUsableTick(key.tickSpacing),
            tickUpper: TickMath.maxUsableTick(key.tickSpacing)
        });

        (initialTokenId,) = posm.mint(
            config,
            1000e18,
            MAX_SLIPPAGE_ADD_LIQUIDITY,
            MAX_SLIPPAGE_ADD_LIQUIDITY,
            address(this),
            block.timestamp,
            ZERO_BYTES
        );

        address token0 = Currency.unwrap(currency0);
        address token1 = Currency.unwrap(currency1);

        hook.setPriceFeed(address(token0), address(priceFeed0));
        hook.setPriceFeed(address(token1), address(priceFeed1));
    }

    /**
     * @notice Test the initialization of the RugGuard contract
     * @dev Verifies that the contract is initialized correctly
     */
    function testInitialization() public view {
        (, uint256 liquidityChangeThreshold, uint256 totalLiquidity, uint256 riskScore,,,) = hook.poolInfo(poolId);

        assertEq(liquidityChangeThreshold, hook.DEFAULT_LIQUIDITY_CHANGE_THRESHOLD());
        assertEq(totalLiquidity, 1000e18);
        assertEq(riskScore, 45);
    }

    /**
     * @notice Test adding liquidity to the pool
     * @dev Verifies that the liquidity change is handled correctly
     */
    function testLiquidityAddition() public {
        uint256 addAmount = 5e18;
        (uint256 newTokenId,) = posm.mint(
            config,
            addAmount,
            MAX_SLIPPAGE_ADD_LIQUIDITY,
            MAX_SLIPPAGE_ADD_LIQUIDITY,
            address(this),
            block.timestamp,
            ZERO_BYTES
        );

        (
            uint256 lastLiquidityChangeTimestamp,
            uint256 liquidityChangeThreshold,
            uint256 totalLiquidity,
            uint256 riskScore,
            uint256 totalVolume24h,
            uint256 lastVolumeUpdateTimestamp,
            int256 lastPrice
        ) = hook.poolInfo(poolId);

        assertEq(totalLiquidity, 1000e18 + addAmount);
        assertEq(riskScore, 40);
        assertEq(lastLiquidityChangeTimestamp, block.timestamp);
        assertEq(lastPrice, 0);
        assertEq(totalVolume24h, 0);
        assertEq(lastVolumeUpdateTimestamp, block.timestamp);
        assertEq(liquidityChangeThreshold, hook.DEFAULT_LIQUIDITY_CHANGE_THRESHOLD());
    }

    /**
     * @notice Test removing liquidity from the pool
     * @dev Verifies that the liquidity change is handled correctly
     */
    function testLiquidityRemoval() public {
        (
            uint256 lastLiquidityChangeTimestamp,
            uint256 liquidityChangeThreshold,
            uint256 initialTotalLiquidity,
            uint256 initialRiskScore,
            uint256 totalVolume24h,
            uint256 lastVolumeUpdateTimestamp,
            int256 lastPrice
        ) = hook.poolInfo(poolId);

        uint256 removeAmount = 10e18;

        posm.decreaseLiquidity(
            initialTokenId,
            config,
            removeAmount,
            MAX_SLIPPAGE_REMOVE_LIQUIDITY,
            MAX_SLIPPAGE_REMOVE_LIQUIDITY,
            address(this),
            block.timestamp,
            ZERO_BYTES
        );

        (
            uint256 finalLastLiquidityChangeTimestamp,
            uint256 finalLiquidityChangeThreshold,
            uint256 finalTotalLiquidity,
            uint256 finalRiskScore,
            uint256 finalTotalVolume24h,
            uint256 finalLastVolumeUpdateTimestamp,
            int256 finalLastPrice
        ) = hook.poolInfo(poolId);

        assertEq(finalTotalLiquidity, initialTotalLiquidity - removeAmount);
        assertEq(finalRiskScore, initialRiskScore);
    }
}
