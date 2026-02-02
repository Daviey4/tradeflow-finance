"""
TradeFlow Mobile App - Pure Python with Flet
=============================================
No JavaScript required! This builds to iOS, Android, Web, and Desktop.

Installation:
    pip install flet requests

Run locally:
    python tradeflow_app.py

Build for mobile:
    flet build apk    # Android
    flet build ipa    # iOS (requires Mac)
    flet build web    # Web app

Documentation: https://flet.dev
"""

import flet as ft
import requests
import json
from datetime import datetime
from typing import Optional
import asyncio

# =============================================================================
# CONFIGURATION
# =============================================================================

# Change this to your deployed Django server
API_BASE_URL = "https://your-tradeflow-server.com"  # or http://localhost:8000
COINGECKO_API = "https://api.coingecko.com/api/v3"

# Colors (matching your web app)
COLORS = {
    "background": "#000000",
    "card": "#18181b",
    "card_border": "#27272a",
    "primary": "#22c55e",
    "danger": "#ef4444",
    "warning": "#f59e0b",
    "text": "#ffffff",
    "text_muted": "#71717a",
    "accent": "#06b6d4",
}

# Assets available for trading
ASSETS = [
    {"id": "bitcoin", "symbol": "BTC", "name": "Bitcoin", "color": "#F7931A"},
    {"id": "ethereum", "symbol": "ETH", "name": "Ethereum", "color": "#627EEA"},
    {"id": "solana", "symbol": "SOL", "name": "Solana", "color": "#00FFA3"},
]


# =============================================================================
# DATA STORAGE (Local - like AsyncStorage in React Native)
# =============================================================================

class LocalStorage:
    """Simple local storage using Flet's client storage"""
    
    def __init__(self, page: ft.Page):
        self.page = page
    
    async def get(self, key: str, default=None):
        try:
            value = await self.page.client_storage.get_async(f"tradeflow_{key}")
            return json.loads(value) if value else default
        except:
            return default
    
    async def set(self, key: str, value):
        try:
            await self.page.client_storage.set_async(f"tradeflow_{key}", json.dumps(value))
        except Exception as e:
            print(f"Storage error: {e}")
    
    async def get_portfolio(self):
        return await self.get("portfolio", {
            "balance": 50000,
            "holdings": {},
            "average_costs": {},
        })
    
    async def save_portfolio(self, portfolio):
        await self.set("portfolio", portfolio)
    
    async def get_trades(self):
        return await self.get("trades", [])
    
    async def add_trade(self, trade):
        trades = await self.get_trades()
        trades.insert(0, trade)
        await self.set("trades", trades[:100])  # Keep last 100


# =============================================================================
# API SERVICE
# =============================================================================

class TradingAPI:
    """API service for price data"""
    
    @staticmethod
    async def get_price(asset_id: str) -> Optional[dict]:
        """Fetch current price from CoinGecko"""
        try:
            url = f"{COINGECKO_API}/simple/price"
            params = {
                "ids": asset_id,
                "vs_currencies": "usd",
                "include_24hr_change": "true"
            }
            
            # Run in thread to avoid blocking
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(
                None, 
                lambda: requests.get(url, params=params, timeout=10)
            )
            
            if response.status_code == 200:
                data = response.json()
                return {
                    "price": data[asset_id]["usd"],
                    "change_24h": data[asset_id].get("usd_24h_change", 0)
                }
        except Exception as e:
            print(f"API Error: {e}")
        return None


# =============================================================================
# MAIN APP
# =============================================================================

async def main(page: ft.Page):
    """Main application entry point"""
    
    # Page configuration
    page.title = "TradeFlow"
    page.theme_mode = ft.ThemeMode.DARK
    page.bgcolor = COLORS["background"]
    page.padding = 0
    
    # Initialize storage
    storage = LocalStorage(page)
    
    # State variables
    current_asset_index = 0
    current_price = None
    price_change = 0
    portfolio = await storage.get_portfolio()
    is_automation_running = False
    
    # ==========================================================================
    # UI COMPONENTS
    # ==========================================================================
    
    def create_card(content, **kwargs):
        """Create a styled card container"""
        return ft.Container(
            content=content,
            bgcolor=COLORS["card"],
            border=ft.border.all(1, COLORS["card_border"]),
            border_radius=20,
            padding=20,
            **kwargs
        )
    
    def create_stat_card(label: str, value: str, color: str = COLORS["text"]):
        """Create a statistics card"""
        return create_card(
            ft.Column([
                ft.Text(label, size=12, color=COLORS["text_muted"], 
                       weight=ft.FontWeight.W_500),
                ft.Text(value, size=20, color=color, weight=ft.FontWeight.BOLD),
            ], spacing=4),
            expand=True,
        )
    
    # --------------------------------------------------------------------------
    # Header
    # --------------------------------------------------------------------------
    
    status_indicator = ft.Container(
        content=ft.Row([
            ft.Container(
                width=8, height=8,
                bgcolor=COLORS["primary"],
                border_radius=4,
            ),
            ft.Text("Live", size=12, color=COLORS["primary"], weight=ft.FontWeight.W_600),
        ], spacing=6),
        bgcolor=f"{COLORS['primary']}20",
        padding=ft.padding.symmetric(horizontal=12, vertical=6),
        border_radius=20,
    )
    
    header = ft.Container(
        content=ft.Row([
            ft.Row([
                ft.Container(
                    content=ft.Text("⚡", size=20),
                    width=40, height=40,
                    bgcolor=COLORS["primary"],
                    border_radius=12,
                    alignment=ft.alignment.center,
                ),
                ft.Column([
                    ft.Text("TradeFlow", size=20, weight=ft.FontWeight.BOLD, color=COLORS["text"]),
                    ft.Text("Automated Trading", size=11, color=COLORS["text_muted"]),
                ], spacing=0),
            ], spacing=12),
            status_indicator,
        ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
        padding=20,
    )
    
    # --------------------------------------------------------------------------
    # Portfolio Stats
    # --------------------------------------------------------------------------
    
    portfolio_value_text = ft.Text("$50,000.00", size=20, color=COLORS["text"], 
                                    weight=ft.FontWeight.BOLD)
    total_pl_text = ft.Text("$0.00", size=20, color=COLORS["primary"], 
                            weight=ft.FontWeight.BOLD)
    
    stats_row = ft.Row([
        create_card(
            ft.Column([
                ft.Text("Portfolio Value", size=12, color=COLORS["text_muted"]),
                portfolio_value_text,
            ], spacing=4),
            expand=True,
        ),
        create_card(
            ft.Column([
                ft.Text("Total P/L", size=12, color=COLORS["text_muted"]),
                total_pl_text,
            ], spacing=4),
            expand=True,
        ),
    ], spacing=12)
    
    # --------------------------------------------------------------------------
    # Asset Selector
    # --------------------------------------------------------------------------
    
    def create_asset_button(index: int, asset: dict, selected: bool):
        return ft.Container(
            content=ft.Text(
                asset["symbol"],
                color=COLORS["background"] if selected else COLORS["text_muted"],
                weight=ft.FontWeight.W_600,
            ),
            bgcolor=COLORS["text"] if selected else COLORS["card"],
            border=ft.border.all(1, COLORS["text"] if selected else COLORS["card_border"]),
            border_radius=12,
            padding=ft.padding.symmetric(horizontal=16, vertical=12),
            expand=True,
            alignment=ft.alignment.center,
            on_click=lambda e, idx=index: select_asset(idx),
        )
    
    asset_buttons_row = ft.Row(spacing=8)
    
    def update_asset_buttons():
        asset_buttons_row.controls = [
            create_asset_button(i, asset, i == current_asset_index)
            for i, asset in enumerate(ASSETS)
        ]
    
    update_asset_buttons()
    
    # --------------------------------------------------------------------------
    # Price Display
    # --------------------------------------------------------------------------
    
    asset_name_text = ft.Text("Bitcoin", size=18, weight=ft.FontWeight.W_600, 
                              color=COLORS["text"])
    asset_symbol_text = ft.Text("BTC", size=14, color=COLORS["text_muted"])
    price_text = ft.Text("$---", size=28, weight=ft.FontWeight.BOLD, color=COLORS["text"])
    price_change_text = ft.Text("↑ 0.00%", size=14, color=COLORS["primary"])
    
    price_card = create_card(
        ft.Row([
            ft.Column([
                asset_name_text,
                asset_symbol_text,
            ], spacing=0),
            ft.Column([
                price_text,
                price_change_text,
            ], spacing=0, horizontal_alignment=ft.CrossAxisAlignment.END),
        ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
    )
    
    # --------------------------------------------------------------------------
    # Holdings Display
    # --------------------------------------------------------------------------
    
    holdings_amount_text = ft.Text("0.000000", color=COLORS["text"], weight=ft.FontWeight.W_600)
    holdings_value_text = ft.Text("$0.00", color=COLORS["text"], weight=ft.FontWeight.W_600)
    avg_cost_text = ft.Text("$0.00", color=COLORS["text"], weight=ft.FontWeight.W_600)
    unrealized_pl_text = ft.Text("$0.00", color=COLORS["primary"], weight=ft.FontWeight.W_600)
    
    holdings_card = create_card(
        ft.Column([
            ft.Text("Your Holdings", size=18, weight=ft.FontWeight.W_600, color=COLORS["text"]),
            ft.Divider(height=20, color=COLORS["card_border"]),
            ft.Row([ft.Text("Amount", color=COLORS["text_muted"]), holdings_amount_text], 
                   alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
            ft.Row([ft.Text("Value", color=COLORS["text_muted"]), holdings_value_text], 
                   alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
            ft.Row([ft.Text("Avg Cost", color=COLORS["text_muted"]), avg_cost_text], 
                   alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
            ft.Divider(height=20, color=COLORS["card_border"]),
            ft.Row([ft.Text("Unrealized P/L", color=COLORS["text_muted"]), unrealized_pl_text], 
                   alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
        ], spacing=12),
    )
    
    # --------------------------------------------------------------------------
    # Trading Controls
    # --------------------------------------------------------------------------
    
    buy_threshold_input = ft.TextField(
        label="Buy Below",
        value="0",
        keyboard_type=ft.KeyboardType.NUMBER,
        bgcolor=COLORS["background"],
        border_color=COLORS["card_border"],
        color=COLORS["primary"],
        label_style=ft.TextStyle(color=COLORS["text_muted"]),
        expand=True,
    )
    
    sell_threshold_input = ft.TextField(
        label="Sell Above",
        value="0",
        keyboard_type=ft.KeyboardType.NUMBER,
        bgcolor=COLORS["background"],
        border_color=COLORS["card_border"],
        color=COLORS["danger"],
        label_style=ft.TextStyle(color=COLORS["text_muted"]),
        expand=True,
    )
    
    trade_amount_input = ft.TextField(
        label="Trade Amount",
        value="0.01",
        keyboard_type=ft.KeyboardType.NUMBER,
        bgcolor=COLORS["background"],
        border_color=COLORS["card_border"],
        color=COLORS["text"],
        label_style=ft.TextStyle(color=COLORS["text_muted"]),
    )
    
    automation_button = ft.ElevatedButton(
        content=ft.Text("▶ Start Automation", weight=ft.FontWeight.W_600),
        style=ft.ButtonStyle(
            bgcolor=COLORS["primary"],
            color=COLORS["text"],
            padding=16,
            shape=ft.RoundedRectangleBorder(radius=14),
        ),
        width=float("inf"),
    )
    
    trading_card = create_card(
        ft.Column([
            ft.Text("Automation", size=18, weight=ft.FontWeight.W_600, color=COLORS["text"]),
            ft.Row([buy_threshold_input, sell_threshold_input], spacing=12),
            trade_amount_input,
            automation_button,
        ], spacing=16),
    )
    
    # --------------------------------------------------------------------------
    # Manual Trade Buttons
    # --------------------------------------------------------------------------
    
    def create_trade_button(text: str, color: str, on_click):
        return ft.Container(
            content=ft.Text(text, weight=ft.FontWeight.W_600, color=COLORS["text"]),
            bgcolor=f"{color}20",
            border=ft.border.all(1, f"{color}40"),
            border_radius=14,
            padding=16,
            expand=True,
            alignment=ft.alignment.center,
            on_click=on_click,
        )
    
    trade_buttons = ft.Row([
        create_trade_button("Buy", COLORS["primary"], lambda e: execute_trade("buy")),
        create_trade_button("Sell", COLORS["danger"], lambda e: execute_trade("sell")),
    ], spacing=12)
    
    # --------------------------------------------------------------------------
    # Balance Display
    # --------------------------------------------------------------------------
    
    balance_text = ft.Text("$50,000.00", size=14, color=COLORS["text_muted"])
    
    balance_row = ft.Container(
        content=ft.Row([
            ft.Text("Available:", color=COLORS["text_muted"]),
            balance_text,
        ], alignment=ft.MainAxisAlignment.CENTER),
        padding=10,
    )
    
    # ==========================================================================
    # EVENT HANDLERS
    # ==========================================================================
    
    def select_asset(index: int):
        nonlocal current_asset_index, current_price
        current_asset_index = index
        current_price = None
        update_asset_buttons()
        update_display()
        page.update()
        # Fetch new price
        page.run_task(fetch_price)
    
    async def fetch_price():
        nonlocal current_price, price_change
        asset = ASSETS[current_asset_index]
        data = await TradingAPI.get_price(asset["id"])
        
        if data:
            current_price = data["price"]
            price_change = data["change_24h"]
            
            # Update thresholds if empty
            if buy_threshold_input.value == "0":
                buy_threshold_input.value = str(int(current_price * 0.97))
                sell_threshold_input.value = str(int(current_price * 1.03))
            
            update_display()
            page.update()
    
    def update_display():
        nonlocal portfolio
        
        asset = ASSETS[current_asset_index]
        asset_id = asset["id"]
        
        # Update asset info
        asset_name_text.value = asset["name"]
        asset_symbol_text.value = asset["symbol"]
        
        # Update price
        if current_price:
            price_text.value = f"${current_price:,.2f}"
            change_symbol = "↑" if price_change >= 0 else "↓"
            price_change_text.value = f"{change_symbol} {abs(price_change):.2f}%"
            price_change_text.color = COLORS["primary"] if price_change >= 0 else COLORS["danger"]
        else:
            price_text.value = "$---"
        
        # Update holdings
        holdings = portfolio.get("holdings", {}).get(asset_id, 0)
        avg_cost = portfolio.get("average_costs", {}).get(asset_id, 0)
        holdings_value = holdings * (current_price or 0)
        unrealized_pl = (current_price - avg_cost) * holdings if holdings > 0 and current_price else 0
        
        holdings_amount_text.value = f"{holdings:.6f}"
        holdings_value_text.value = f"${holdings_value:,.2f}"
        avg_cost_text.value = f"${avg_cost:,.2f}"
        unrealized_pl_text.value = f"{'+'if unrealized_pl >= 0 else ''}${unrealized_pl:,.2f}"
        unrealized_pl_text.color = COLORS["primary"] if unrealized_pl >= 0 else COLORS["danger"]
        
        # Update portfolio stats
        total_holdings_value = sum(
            portfolio.get("holdings", {}).get(a["id"], 0) * (current_price if a["id"] == asset_id else 0)
            for a in ASSETS
        )
        portfolio_value = portfolio["balance"] + holdings_value
        total_pl = portfolio_value - 50000
        
        portfolio_value_text.value = f"${portfolio_value:,.2f}"
        total_pl_text.value = f"{'+'if total_pl >= 0 else ''}${total_pl:,.2f}"
        total_pl_text.color = COLORS["primary"] if total_pl >= 0 else COLORS["danger"]
        
        # Update balance
        balance_text.value = f"${portfolio['balance']:,.2f}"
    
    async def execute_trade(trade_type: str):
        nonlocal portfolio
        
        if not current_price:
            show_snackbar("Price not available", COLORS["danger"])
            return
        
        try:
            amount = float(trade_amount_input.value)
        except:
            show_snackbar("Invalid amount", COLORS["danger"])
            return
        
        asset = ASSETS[current_asset_index]
        asset_id = asset["id"]
        cost = current_price * amount
        
        if trade_type == "buy":
            if portfolio["balance"] < cost:
                show_snackbar("Insufficient balance", COLORS["danger"])
                return
            
            current_holdings = portfolio.get("holdings", {}).get(asset_id, 0)
            current_avg = portfolio.get("average_costs", {}).get(asset_id, 0)
            new_holdings = current_holdings + amount
            new_avg = ((current_avg * current_holdings) + cost) / new_holdings if current_holdings > 0 else current_price
            
            portfolio["balance"] -= cost
            portfolio.setdefault("holdings", {})[asset_id] = new_holdings
            portfolio.setdefault("average_costs", {})[asset_id] = new_avg
            
            show_snackbar(f"Bought {amount} {asset['symbol']}", COLORS["primary"])
        
        else:  # sell
            current_holdings = portfolio.get("holdings", {}).get(asset_id, 0)
            if current_holdings < amount:
                show_snackbar("Insufficient holdings", COLORS["danger"])
                return
            
            avg_cost = portfolio.get("average_costs", {}).get(asset_id, 0)
            profit = (current_price - avg_cost) * amount
            
            portfolio["balance"] += cost
            portfolio["holdings"][asset_id] = current_holdings - amount
            
            # Save trade
            await storage.add_trade({
                "type": "SELL",
                "asset": asset_id,
                "symbol": asset["symbol"],
                "amount": amount,
                "price": current_price,
                "total": cost,
                "profit": profit,
                "time": datetime.now().isoformat(),
            })
            
            show_snackbar(f"Sold {amount} {asset['symbol']} (P/L: ${profit:.2f})", 
                         COLORS["primary"] if profit >= 0 else COLORS["danger"])
        
        # Save buy trade
        if trade_type == "buy":
            await storage.add_trade({
                "type": "BUY",
                "asset": asset_id,
                "symbol": asset["symbol"],
                "amount": amount,
                "price": current_price,
                "total": cost,
                "time": datetime.now().isoformat(),
            })
        
        await storage.save_portfolio(portfolio)
        update_display()
        page.update()
    
    def show_snackbar(message: str, color: str):
        page.snack_bar = ft.SnackBar(
            content=ft.Text(message, color=COLORS["text"]),
            bgcolor=color,
        )
        page.snack_bar.open = True
        page.update()
    
    def toggle_automation(e):
        nonlocal is_automation_running
        is_automation_running = not is_automation_running
        
        if is_automation_running:
            automation_button.content = ft.Text("⏹ Stop Automation", weight=ft.FontWeight.W_600)
            automation_button.style.bgcolor = COLORS["danger"]
            show_snackbar("Automation started", COLORS["primary"])
        else:
            automation_button.content = ft.Text("▶ Start Automation", weight=ft.FontWeight.W_600)
            automation_button.style.bgcolor = COLORS["primary"]
            show_snackbar("Automation stopped", COLORS["warning"])
        
        page.update()
    
    automation_button.on_click = toggle_automation
    
    # ==========================================================================
    # PRICE UPDATE LOOP
    # ==========================================================================
    
    async def price_update_loop():
        while True:
            await fetch_price()
            
            # Check automation
            if is_automation_running and current_price:
                try:
                    buy_price = float(buy_threshold_input.value)
                    sell_price = float(sell_threshold_input.value)
                    amount = float(trade_amount_input.value)
                    
                    asset_id = ASSETS[current_asset_index]["id"]
                    holdings = portfolio.get("holdings", {}).get(asset_id, 0)
                    
                    if current_price <= buy_price and portfolio["balance"] >= current_price * amount:
                        await execute_trade("buy")
                    elif current_price >= sell_price and holdings >= amount:
                        await execute_trade("sell")
                except:
                    pass
            
            await asyncio.sleep(10)  # Update every 10 seconds
    
    # ==========================================================================
    # BUILD PAGE
    # ==========================================================================
    
    # Main content (scrollable)
    content = ft.Column([
        header,
        ft.Container(
            content=ft.Column([
                stats_row,
                ft.Container(height=12),
                asset_buttons_row,
                ft.Container(height=12),
                price_card,
                ft.Container(height=12),
                holdings_card,
                ft.Container(height=12),
                trading_card,
                ft.Container(height=12),
                trade_buttons,
                balance_row,
                ft.Container(height=100),  # Bottom padding for nav
            ], spacing=0),
            padding=ft.padding.symmetric(horizontal=20),
        ),
    ], spacing=0, scroll=ft.ScrollMode.AUTO)
    
    # Navigation bar
    nav_bar = ft.NavigationBar(
        destinations=[
            ft.NavigationBarDestination(icon=ft.icons.DASHBOARD, label="Dashboard"),
            ft.NavigationBarDestination(icon=ft.icons.HISTORY, label="Trades"),
            ft.NavigationBarDestination(icon=ft.icons.CALCULATE, label="Calculator"),
            ft.NavigationBarDestination(icon=ft.icons.SETTINGS, label="Settings"),
        ],
        bgcolor=COLORS["card"],
        indicator_color=COLORS["primary"],
        selected_index=0,
    )
    
    # Add to page
    page.add(
        ft.Column([
            ft.Container(content=content, expand=True),
            nav_bar,
        ], spacing=0, expand=True)
    )
    
    # Initial data load
    portfolio = await storage.get_portfolio()
    update_display()
    
    # Start price updates
    page.run_task(price_update_loop)


# =============================================================================
# RUN APP
# =============================================================================

if __name__ == "__main__":
    ft.app(target=main)
    
    # For web deployment:
    # ft.app(target=main, view=ft.AppView.WEB_BROWSER)
    
    # For specific port:
    # ft.app(target=main, port=8550)
