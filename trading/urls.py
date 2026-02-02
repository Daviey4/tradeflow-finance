from django.urls import path
from . import views
from . import alpaca_views

app_name = 'trading'

urlpatterns = [
    # Pages
    path('', views.dashboard, name='dashboard'),
    path('trades/', views.trades_view, name='trades'),
    path('alerts/', views.alerts_view, name='alerts'),
    path('calculator/', views.calculator_view, name='calculator'),
    path('security-lab/', views.security_lab_view, name='security_lab'),
    path('live/', alpaca_views.alpaca_dashboard, name='live_trading'),
    
    # API endpoints
    path('api/price/<str:asset_id>/', views.api_price, name='api_price'),
    path('api/price-history/<str:asset_id>/', views.api_price_history, name='api_price_history'),
    path('api/portfolio/', views.api_portfolio, name='api_portfolio'),
    path('api/trade/', views.api_trade, name='api_trade'),
    path('api/strategy/', views.api_strategy, name='api_strategy'),
    path('api/notifications/clear/', views.api_clear_notifications, name='api_clear_notifications'),
    path('api/portfolio/reset/', views.api_reset_portfolio, name='api_reset_portfolio'),
    
    # Alpaca API endpoints
    path('api/alpaca/account/', alpaca_views.api_alpaca_account, name='api_alpaca_account'),
    path('api/alpaca/positions/', alpaca_views.api_alpaca_positions, name='api_alpaca_positions'),
    path('api/alpaca/price/<str:symbol>/', alpaca_views.api_alpaca_price, name='api_alpaca_price'),
    path('api/alpaca/history/<str:symbol>/', alpaca_views.api_alpaca_history, name='api_alpaca_history'),
    path('api/alpaca/buy/', alpaca_views.api_alpaca_buy, name='api_alpaca_buy'),
    path('api/alpaca/sell/', alpaca_views.api_alpaca_sell, name='api_alpaca_sell'),
    path('api/alpaca/orders/', alpaca_views.api_alpaca_orders, name='api_alpaca_orders'),
]
