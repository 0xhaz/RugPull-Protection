// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {IHooks} from "v4-core/interfaces/IHooks.sol";
import {Hooks} from "v4-core/libraries/Hooks.sol";
import {TickMath} from "v4-core/libraries/TickMath.sol";
import {IPoolManager} from "v4-core/interfaces/IPoolManager.sol";
import {PoolKey} from "v4-core/types/PoolKey.sol";
import {BalanceDelta} from "v4-core/types/BalanceDelta.sol";
import {PoolId, PoolIdLibrary} from "v4-core/types/PoolId.sol";
import {CurrencyLibrary, Currency} from "v4-core/types/Currency.sol";
import {StateLibrary} from "v4-core/libraries/StateLibrary.sol";
import {PositionConfig} from "v4-periphery/src/libraries/PositionConfig.sol";
import {LiquidityAmounts} from "@uniswap/v4-core/test/utils/LiquidityAmounts.sol";

import {IPositionManager} from "v4-periphery/src/interfaces/IPositionManager.sol";
import {EasyPosm} from "./EasyPosm.sol";
import {Fixtures} from "./Fixtures.sol";

contract CounterTest is Test, Fixtures {
    using EasyPosm for IPositionManager;
    using PoolIdLibrary for PoolKey;
    using CurrencyLibrary for Currency;
    using StateLibrary for IPoolManager;

    PositionConfig config;

    function setUp() public {
        // creates the pool manager, utility routers, and test tokens
        deployFreshManagerAndRouters();
        deployMintAndApprove2Currencies();

        deployAndApprovePosm(manager);

        // Create the pool
        key = PoolKey(currency0, currency1, 3000, 60, IHooks(address(0)));
        manager.initialize(key, SQRT_PRICE_1_1, ZERO_BYTES);

        // full-range liquidity
        config = PositionConfig({
            poolKey: key,
            tickLower: TickMath.minUsableTick(key.tickSpacing),
            tickUpper: TickMath.maxUsableTick(key.tickSpacing)
        });
    }

    function test_mintLiquidity() public {
        uint256 liquidityToMint = 100e18;
        address recipient = address(this);

        (uint256 amount0, uint256 amount1) = LiquidityAmounts.getAmountsForLiquidity(
            SQRT_PRICE_1_1,
            TickMath.getSqrtPriceAtTick(config.tickLower),
            TickMath.getSqrtPriceAtTick(config.tickUpper),
            uint128(liquidityToMint)
        );

        (, BalanceDelta delta) = posm.mint(
            config,
            liquidityToMint,
            MAX_SLIPPAGE_ADD_LIQUIDITY,
            MAX_SLIPPAGE_ADD_LIQUIDITY,
            recipient,
            block.timestamp + 1,
            ZERO_BYTES
        );
        assertEq(delta.amount0(), -int128(uint128(amount0 + 1 wei)));
        assertEq(delta.amount1(), -int128(uint128(amount1 + 1 wei)));
    }

    function test_increaseLiquidity() public {
        (uint256 tokenId,) = posm.mint(
            config,
            100e18,
            MAX_SLIPPAGE_ADD_LIQUIDITY,
            MAX_SLIPPAGE_ADD_LIQUIDITY,
            address(this),
            block.timestamp + 1,
            ZERO_BYTES
        );

        uint256 liquidityToAdd = 1e18;

        (uint256 amount0, uint256 amount1) = LiquidityAmounts.getAmountsForLiquidity(
            SQRT_PRICE_1_1,
            TickMath.getSqrtPriceAtTick(config.tickLower),
            TickMath.getSqrtPriceAtTick(config.tickUpper),
            uint128(liquidityToAdd)
        );

        BalanceDelta delta = posm.increaseLiquidity(
            tokenId,
            config,
            liquidityToAdd,
            MAX_SLIPPAGE_ADD_LIQUIDITY,
            MAX_SLIPPAGE_ADD_LIQUIDITY,
            block.timestamp + 1,
            ZERO_BYTES
        );
        assertEq(delta.amount0(), -int128(uint128(amount0 + 1 wei)));
        assertEq(delta.amount1(), -int128(uint128(amount1 + 1 wei)));
    }

    function test_decreaseLiquidity() public {
        (uint256 tokenId,) = posm.mint(
            config,
            100e18,
            MAX_SLIPPAGE_ADD_LIQUIDITY,
            MAX_SLIPPAGE_ADD_LIQUIDITY,
            address(this),
            block.timestamp + 1,
            ZERO_BYTES
        );

        uint256 liquidityToRemove = 1e18;

        (uint256 amount0, uint256 amount1) = LiquidityAmounts.getAmountsForLiquidity(
            SQRT_PRICE_1_1,
            TickMath.getSqrtPriceAtTick(config.tickLower),
            TickMath.getSqrtPriceAtTick(config.tickUpper),
            uint128(liquidityToRemove)
        );

        BalanceDelta delta = posm.decreaseLiquidity(
            tokenId,
            config,
            liquidityToRemove,
            MAX_SLIPPAGE_REMOVE_LIQUIDITY,
            MAX_SLIPPAGE_REMOVE_LIQUIDITY,
            address(this),
            block.timestamp + 1,
            ZERO_BYTES
        );
        assertEq(delta.amount0(), int128(uint128(amount0)));
        assertEq(delta.amount1(), int128(uint128(amount1)));
    }

    function test_burn() public {
        (uint256 tokenId, BalanceDelta mintDelta) = posm.mint(
            config,
            10_000 ether,
            MAX_SLIPPAGE_ADD_LIQUIDITY,
            MAX_SLIPPAGE_ADD_LIQUIDITY,
            address(this),
            block.timestamp + 1,
            ZERO_BYTES
        );

        BalanceDelta delta = posm.burn(
            tokenId,
            config,
            MAX_SLIPPAGE_REMOVE_LIQUIDITY,
            MAX_SLIPPAGE_REMOVE_LIQUIDITY,
            address(this),
            block.timestamp + 1,
            ZERO_BYTES
        );
        assertEq(delta.amount0(), -mintDelta.amount0() - 1 wei);
        assertEq(delta.amount1(), -mintDelta.amount1() - 1 wei);
    }

    function test_collect() public {
        (uint256 tokenId,) = posm.mint(
            config,
            10_000 ether,
            MAX_SLIPPAGE_ADD_LIQUIDITY,
            MAX_SLIPPAGE_ADD_LIQUIDITY,
            address(this),
            block.timestamp + 1,
            ZERO_BYTES
        );

        // donate to regenerate fee revenue
        uint128 feeRevenue0 = 1e18;
        uint128 feeRevenue1 = 0.1e18;
        donateRouter.donate(key, feeRevenue0, feeRevenue1, ZERO_BYTES);

        // position collects half of the revenue since 50% of the liquidity is minted in setUp()
        BalanceDelta delta = posm.collect(
            tokenId,
            config,
            MAX_SLIPPAGE_REMOVE_LIQUIDITY,
            MAX_SLIPPAGE_REMOVE_LIQUIDITY,
            address(0x123),
            block.timestamp + 1,
            ZERO_BYTES
        );
        assertEq(uint128(delta.amount0()), feeRevenue0 - 1 wei);
        assertEq(uint128(delta.amount1()), feeRevenue1 - 1 wei);
    }
}
