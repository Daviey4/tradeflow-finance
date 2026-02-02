from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from decimal import Decimal


class Portfolio(models.Model):
    """User's trading portfolio"""
    user = models.OneToOneField(User, on_delete=models.CASCADE, null=True, blank=True)
    session_id = models.CharField(max_length=100, unique=True, null=True, blank=True)
    balance = models.DecimalField(max_digits=20, decimal_places=2, default=50000.00)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        if self.user:
            return f"Portfolio - {self.user.username}"
        return f"Portfolio - Session {self.session_id[:8]}"

    @property
    def total_value(self):
        """Calculate total portfolio value including holdings"""
        holdings_value = sum(h.current_value for h in self.holdings.all())
        return self.balance + Decimal(str(holdings_value))


class Holding(models.Model):
    """Cryptocurrency holdings"""
    portfolio = models.ForeignKey(Portfolio, on_delete=models.CASCADE, related_name='holdings')
    asset_id = models.CharField(max_length=50)  # e.g., 'bitcoin'
    symbol = models.CharField(max_length=10)  # e.g., 'BTC'
    amount = models.DecimalField(max_digits=20, decimal_places=8, default=0)
    average_cost = models.DecimalField(max_digits=20, decimal_places=2, default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ['portfolio', 'asset_id']

    def __str__(self):
        return f"{self.amount} {self.symbol}"

    @property
    def current_value(self):
        """Get current value (needs price from API)"""
        # This will be calculated in the view with current price
        return 0


class Trade(models.Model):
    """Trade history"""
    TRADE_TYPES = [
        ('BUY', 'Buy'),
        ('SELL', 'Sell'),
    ]

    portfolio = models.ForeignKey(Portfolio, on_delete=models.CASCADE, related_name='trades')
    trade_type = models.CharField(max_length=4, choices=TRADE_TYPES)
    asset_id = models.CharField(max_length=50)
    symbol = models.CharField(max_length=10)
    amount = models.DecimalField(max_digits=20, decimal_places=8)
    price = models.DecimalField(max_digits=20, decimal_places=2)
    total = models.DecimalField(max_digits=20, decimal_places=2)
    profit = models.DecimalField(max_digits=20, decimal_places=2, null=True, blank=True)
    reason = models.CharField(max_length=200, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.trade_type} {self.amount} {self.symbol} @ ${self.price}"


class TradingStrategy(models.Model):
    """Trading automation strategy configuration"""
    STRATEGY_TYPES = [
        ('threshold', 'Threshold'),
        ('trailing', 'Trailing Stop'),
        ('dca', 'Dollar Cost Averaging'),
    ]

    portfolio = models.ForeignKey(Portfolio, on_delete=models.CASCADE, related_name='strategies')
    asset_id = models.CharField(max_length=50)
    symbol = models.CharField(max_length=10)
    strategy_type = models.CharField(max_length=20, choices=STRATEGY_TYPES, default='threshold')
    is_active = models.BooleanField(default=False)
    
    # Threshold strategy settings
    buy_threshold = models.DecimalField(max_digits=20, decimal_places=2, default=0)
    sell_threshold = models.DecimalField(max_digits=20, decimal_places=2, default=0)
    trade_amount = models.DecimalField(max_digits=20, decimal_places=8, default=0.01)
    
    # Trailing stop settings
    trailing_percent = models.DecimalField(max_digits=5, decimal_places=2, default=5.00)
    highest_price = models.DecimalField(max_digits=20, decimal_places=2, default=0)
    lowest_price = models.DecimalField(max_digits=20, decimal_places=2, null=True, blank=True)
    trailing_stop_price = models.DecimalField(max_digits=20, decimal_places=2, default=0)
    trailing_buy_price = models.DecimalField(max_digits=20, decimal_places=2, null=True, blank=True)
    
    # DCA settings
    dca_interval = models.IntegerField(default=60)  # seconds
    dca_amount = models.DecimalField(max_digits=20, decimal_places=2, default=100)
    last_dca_time = models.DateTimeField(null=True, blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ['portfolio', 'asset_id']

    def __str__(self):
        return f"{self.strategy_type} - {self.symbol}"


class Notification(models.Model):
    """User notifications"""
    NOTIFICATION_TYPES = [
        ('buy', 'Buy'),
        ('sell', 'Sell'),
        ('alert', 'Alert'),
        ('system', 'System'),
    ]

    portfolio = models.ForeignKey(Portfolio, on_delete=models.CASCADE, related_name='notifications')
    notification_type = models.CharField(max_length=10, choices=NOTIFICATION_TYPES)
    message = models.TextField()
    is_read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.notification_type}: {self.message[:50]}"


class PriceHistory(models.Model):
    """Store price history for charts"""
    asset_id = models.CharField(max_length=50)
    price = models.DecimalField(max_digits=20, decimal_places=2)
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['asset_id', '-timestamp']),
        ]

    def __str__(self):
        return f"{self.asset_id}: ${self.price}"
