"""
Alpaca Trading Integration for TradeFlow

This module provides real stock/crypto trading via Alpaca's API.
Alpaca offers:
- Free stock trading (no commissions)
- Free API access
- Paper trading for testing
- Real-time market data

Setup:
1. Create account at https://alpaca.markets
2. Get your API keys from the dashboard
3. Add keys to your Django settings or .env file
"""

import os
from decimal import Decimal
from datetime import datetime, timedelta
from django.conf import settings

# Try to import alpaca-trade-api
try:
    from alpaca.trading.client import TradingClient
    from alpaca.trading.requests import MarketOrderRequest, LimitOrderRequest
    from alpaca.trading.enums import OrderSide, TimeInForce
    from alpaca.data.historical import StockHistoricalDataClient
    from alpaca.data.requests import StockLatestQuoteRequest, StockBarsRequest
    from alpaca.data.timeframe import TimeFrame
    ALPACA_AVAILABLE = True
except ImportError:
    ALPACA_AVAILABLE = False
    print("Alpaca not installed. Run: pip install alpaca-py")


class AlpacaTrader:
    """
    Alpaca Trading Client for TradeFlow
    
    Usage:
        trader = AlpacaTrader()
        
        # Get account info
        account = trader.get_account()
        
        # Get live price
        price = trader.get_price('AAPL')
        
        # Buy stock
        order = trader.buy('AAPL', quantity=1)
        
        # Sell stock
        order = trader.sell('AAPL', quantity=1)
    """
    
    def __init__(self, api_key=None, secret_key=None, paper=True):
        """
        Initialize Alpaca client
        
        Args:
            api_key: Alpaca API key (or set ALPACA_API_KEY env var)
            secret_key: Alpaca secret key (or set ALPACA_SECRET_KEY env var)
            paper: Use paper trading (default True for safety)
        """
        if not ALPACA_AVAILABLE:
            raise ImportError("Please install alpaca-py: pip install alpaca-py")
        
        self.api_key = api_key or os.getenv('ALPACA_API_KEY') or getattr(settings, 'ALPACA_API_KEY', None)
        self.secret_key = secret_key or os.getenv('ALPACA_SECRET_KEY') or getattr(settings, 'ALPACA_SECRET_KEY', None)
        self.paper = paper
        
        if not self.api_key or not self.secret_key:
            raise ValueError(
                "Alpaca API keys not found. Set ALPACA_API_KEY and ALPACA_SECRET_KEY "
                "in environment variables or Django settings."
            )
        
        # Initialize trading client
        self.trading_client = TradingClient(
            api_key=self.api_key,
            secret_key=self.secret_key,
            paper=self.paper
        )
        
        # Initialize data client
        self.data_client = StockHistoricalDataClient(
            api_key=self.api_key,
            secret_key=self.secret_key
        )
    
    def get_account(self):
        """Get account information"""
        account = self.trading_client.get_account()
        return {
            'id': account.id,
            'cash': float(account.cash),
            'portfolio_value': float(account.portfolio_value),
            'buying_power': float(account.buying_power),
            'equity': float(account.equity),
            'status': account.status,
            'currency': account.currency,
            'pattern_day_trader': account.pattern_day_trader,
            'trading_blocked': account.trading_blocked,
            'account_blocked': account.account_blocked,
        }
    
    def get_positions(self):
        """Get all current positions"""
        positions = self.trading_client.get_all_positions()
        return [
            {
                'symbol': pos.symbol,
                'quantity': float(pos.qty),
                'market_value': float(pos.market_value),
                'cost_basis': float(pos.cost_basis),
                'unrealized_pl': float(pos.unrealized_pl),
                'unrealized_plpc': float(pos.unrealized_plpc),
                'current_price': float(pos.current_price),
                'avg_entry_price': float(pos.avg_entry_price),
            }
            for pos in positions
        ]
    
    def get_position(self, symbol):
        """Get position for a specific symbol"""
        try:
            pos = self.trading_client.get_open_position(symbol)
            return {
                'symbol': pos.symbol,
                'quantity': float(pos.qty),
                'market_value': float(pos.market_value),
                'cost_basis': float(pos.cost_basis),
                'unrealized_pl': float(pos.unrealized_pl),
                'current_price': float(pos.current_price),
                'avg_entry_price': float(pos.avg_entry_price),
            }
        except Exception:
            return None
    
    def get_price(self, symbol):
        """Get current price for a symbol"""
        request = StockLatestQuoteRequest(symbol_or_symbols=symbol)
        quote = self.data_client.get_stock_latest_quote(request)
        
        if symbol in quote:
            q = quote[symbol]
            return {
                'symbol': symbol,
                'bid': float(q.bid_price),
                'ask': float(q.ask_price),
                'price': float(q.ask_price),  # Use ask as current price
                'timestamp': q.timestamp.isoformat(),
            }
        return None
    
    def get_prices(self, symbols):
        """Get current prices for multiple symbols"""
        request = StockLatestQuoteRequest(symbol_or_symbols=symbols)
        quotes = self.data_client.get_stock_latest_quote(request)
        
        return {
            symbol: {
                'symbol': symbol,
                'bid': float(q.bid_price),
                'ask': float(q.ask_price),
                'price': float(q.ask_price),
                'timestamp': q.timestamp.isoformat(),
            }
            for symbol, q in quotes.items()
        }
    
    def get_price_history(self, symbol, days=30):
        """Get historical price data"""
        request = StockBarsRequest(
            symbol_or_symbols=symbol,
            timeframe=TimeFrame.Day,
            start=datetime.now() - timedelta(days=days),
        )
        bars = self.data_client.get_stock_bars(request)
        
        if symbol in bars:
            return [
                {
                    'timestamp': bar.timestamp.isoformat(),
                    'open': float(bar.open),
                    'high': float(bar.high),
                    'low': float(bar.low),
                    'close': float(bar.close),
                    'volume': int(bar.volume),
                }
                for bar in bars[symbol]
            ]
        return []
    
    def buy(self, symbol, quantity=None, dollars=None, limit_price=None):
        """
        Buy stock
        
        Args:
            symbol: Stock symbol (e.g., 'AAPL')
            quantity: Number of shares (for whole shares)
            dollars: Dollar amount (for fractional shares)
            limit_price: Optional limit price (market order if not specified)
        """
        if quantity:
            if limit_price:
                order_data = LimitOrderRequest(
                    symbol=symbol,
                    qty=quantity,
                    side=OrderSide.BUY,
                    time_in_force=TimeInForce.DAY,
                    limit_price=limit_price,
                )
            else:
                order_data = MarketOrderRequest(
                    symbol=symbol,
                    qty=quantity,
                    side=OrderSide.BUY,
                    time_in_force=TimeInForce.DAY,
                )
        elif dollars:
            order_data = MarketOrderRequest(
                symbol=symbol,
                notional=dollars,
                side=OrderSide.BUY,
                time_in_force=TimeInForce.DAY,
            )
        else:
            raise ValueError("Must specify either quantity or dollars")
        
        order = self.trading_client.submit_order(order_data)
        return self._format_order(order)
    
    def sell(self, symbol, quantity=None, dollars=None, limit_price=None):
        """
        Sell stock
        
        Args:
            symbol: Stock symbol (e.g., 'AAPL')
            quantity: Number of shares
            dollars: Dollar amount
            limit_price: Optional limit price
        """
        if quantity:
            if limit_price:
                order_data = LimitOrderRequest(
                    symbol=symbol,
                    qty=quantity,
                    side=OrderSide.SELL,
                    time_in_force=TimeInForce.DAY,
                    limit_price=limit_price,
                )
            else:
                order_data = MarketOrderRequest(
                    symbol=symbol,
                    qty=quantity,
                    side=OrderSide.SELL,
                    time_in_force=TimeInForce.DAY,
                )
        elif dollars:
            order_data = MarketOrderRequest(
                symbol=symbol,
                notional=dollars,
                side=OrderSide.SELL,
                time_in_force=TimeInForce.DAY,
            )
        else:
            raise ValueError("Must specify either quantity or dollars")
        
        order = self.trading_client.submit_order(order_data)
        return self._format_order(order)
    
    def get_orders(self, status='all'):
        """Get orders"""
        orders = self.trading_client.get_orders(filter=status)
        return [self._format_order(o) for o in orders]
    
    def cancel_order(self, order_id):
        """Cancel an order"""
        self.trading_client.cancel_order_by_id(order_id)
        return True
    
    def _format_order(self, order):
        """Format order response"""
        return {
            'id': str(order.id),
            'symbol': order.symbol,
            'side': order.side.value,
            'type': order.type.value,
            'quantity': float(order.qty) if order.qty else None,
            'notional': float(order.notional) if order.notional else None,
            'filled_quantity': float(order.filled_qty) if order.filled_qty else 0,
            'filled_avg_price': float(order.filled_avg_price) if order.filled_avg_price else None,
            'status': order.status.value,
            'created_at': order.created_at.isoformat() if order.created_at else None,
            'filled_at': order.filled_at.isoformat() if order.filled_at else None,
        }


class AutoTrader:
    """
    Automated trading strategies using Alpaca
    
    This class implements the same strategies as TradeFlow:
    - Threshold (buy low, sell high)
    - DCA (dollar cost averaging)
    """
    
    def __init__(self, trader: AlpacaTrader):
        self.trader = trader
        self.strategies = {}
    
    def add_threshold_strategy(self, symbol, buy_below, sell_above, quantity):
        """Add a threshold trading strategy"""
        self.strategies[f"{symbol}_threshold"] = {
            'type': 'threshold',
            'symbol': symbol,
            'buy_below': buy_below,
            'sell_above': sell_above,
            'quantity': quantity,
            'active': True,
        }
    
    def add_dca_strategy(self, symbol, amount_usd, interval_seconds=86400):
        """Add a DCA strategy (default: daily)"""
        self.strategies[f"{symbol}_dca"] = {
            'type': 'dca',
            'symbol': symbol,
            'amount_usd': amount_usd,
            'interval': interval_seconds,
            'last_buy': None,
            'active': True,
        }
    
    def check_and_execute(self):
        """Check all strategies and execute trades if conditions are met"""
        results = []
        
        for name, strategy in self.strategies.items():
            if not strategy['active']:
                continue
            
            try:
                if strategy['type'] == 'threshold':
                    result = self._execute_threshold(strategy)
                elif strategy['type'] == 'dca':
                    result = self._execute_dca(strategy)
                else:
                    result = None
                
                if result:
                    results.append(result)
            except Exception as e:
                results.append({
                    'strategy': name,
                    'error': str(e),
                })
        
        return results
    
    def _execute_threshold(self, strategy):
        """Execute threshold strategy"""
        symbol = strategy['symbol']
        price_data = self.trader.get_price(symbol)
        
        if not price_data:
            return None
        
        price = price_data['price']
        
        # Check buy condition
        if price <= strategy['buy_below']:
            account = self.trader.get_account()
            cost = price * strategy['quantity']
            
            if account['buying_power'] >= cost:
                order = self.trader.buy(symbol, quantity=strategy['quantity'])
                return {
                    'strategy': 'threshold',
                    'action': 'BUY',
                    'symbol': symbol,
                    'price': price,
                    'quantity': strategy['quantity'],
                    'order': order,
                }
        
        # Check sell condition
        if price >= strategy['sell_above']:
            position = self.trader.get_position(symbol)
            
            if position and position['quantity'] >= strategy['quantity']:
                order = self.trader.sell(symbol, quantity=strategy['quantity'])
                return {
                    'strategy': 'threshold',
                    'action': 'SELL',
                    'symbol': symbol,
                    'price': price,
                    'quantity': strategy['quantity'],
                    'order': order,
                }
        
        return None
    
    def _execute_dca(self, strategy):
        """Execute DCA strategy"""
        from datetime import datetime
        
        now = datetime.now()
        last_buy = strategy.get('last_buy')
        
        # Check if enough time has passed
        if last_buy:
            elapsed = (now - last_buy).total_seconds()
            if elapsed < strategy['interval']:
                return None
        
        symbol = strategy['symbol']
        amount = strategy['amount_usd']
        
        account = self.trader.get_account()
        
        if account['buying_power'] >= amount:
            order = self.trader.buy(symbol, dollars=amount)
            strategy['last_buy'] = now
            
            return {
                'strategy': 'dca',
                'action': 'BUY',
                'symbol': symbol,
                'amount_usd': amount,
                'order': order,
            }
        
        return None


# Example usage and testing
if __name__ == '__main__':
    # Test with paper trading
    print("Testing Alpaca Integration...")
    print("=" * 50)
    
    try:
        trader = AlpacaTrader(paper=True)
        
        # Get account
        account = trader.get_account()
        print(f"\nAccount Status: {account['status']}")
        print(f"Cash: ${account['cash']:,.2f}")
        print(f"Portfolio Value: ${account['portfolio_value']:,.2f}")
        print(f"Buying Power: ${account['buying_power']:,.2f}")
        
        # Get price
        price = trader.get_price('AAPL')
        if price:
            print(f"\nAAPL Price: ${price['price']:.2f}")
        
        # Get positions
        positions = trader.get_positions()
        print(f"\nPositions: {len(positions)}")
        for pos in positions:
            print(f"  {pos['symbol']}: {pos['quantity']} shares @ ${pos['current_price']:.2f}")
        
        print("\n✅ Alpaca integration working!")
        
    except ImportError as e:
        print(f"❌ {e}")
        print("Install with: pip install alpaca-py")
    except ValueError as e:
        print(f"❌ {e}")
        print("Set your API keys in environment variables")
    except Exception as e:
        print(f"❌ Error: {e}")
