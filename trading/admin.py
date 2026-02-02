from django.contrib import admin
from .models import Portfolio, Holding, Trade, TradingStrategy, Notification, PriceHistory


@admin.register(Portfolio)
class PortfolioAdmin(admin.ModelAdmin):
    list_display = ['id', 'user', 'session_id', 'balance', 'created_at']
    search_fields = ['user__username', 'session_id']


@admin.register(Holding)
class HoldingAdmin(admin.ModelAdmin):
    list_display = ['portfolio', 'symbol', 'amount', 'average_cost', 'updated_at']
    list_filter = ['symbol']


@admin.register(Trade)
class TradeAdmin(admin.ModelAdmin):
    list_display = ['portfolio', 'trade_type', 'symbol', 'amount', 'price', 'total', 'profit', 'created_at']
    list_filter = ['trade_type', 'symbol']
    search_fields = ['reason']


@admin.register(TradingStrategy)
class TradingStrategyAdmin(admin.ModelAdmin):
    list_display = ['portfolio', 'symbol', 'strategy_type', 'is_active', 'buy_threshold', 'sell_threshold']
    list_filter = ['strategy_type', 'is_active', 'symbol']


@admin.register(Notification)
class NotificationAdmin(admin.ModelAdmin):
    list_display = ['portfolio', 'notification_type', 'message', 'is_read', 'created_at']
    list_filter = ['notification_type', 'is_read']


@admin.register(PriceHistory)
class PriceHistoryAdmin(admin.ModelAdmin):
    list_display = ['asset_id', 'price', 'timestamp']
    list_filter = ['asset_id']
