from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from decimal import Decimal

class Category(models.Model):
    """Spending categories"""
    name = models.CharField(max_length=50, unique=True)
    icon = models.CharField(max_length=20, default='💰')
    color = models.CharField(max_length=7, default='#10b981')  # Hex color
    
    class Meta:
        verbose_name_plural = 'Categories'
        ordering = ['name']
    
    def __str__(self):
        return f"{self.icon} {self.name}"

class Transaction(models.Model):
    """Personal finance transactions"""
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='transactions', null=True, blank=True)
    session_id = models.CharField(max_length=100, null=True, blank=True)
    
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    category = models.ForeignKey(Category, on_delete=models.SET_NULL, null=True)
    description = models.CharField(max_length=200)
    date = models.DateField(default=timezone.now)
    
    # Recurring transaction fields
    is_recurring = models.BooleanField(default=False)
    recurring_frequency = models.CharField(
        max_length=20,
        choices=[
            ('daily', 'Daily'),
            ('weekly', 'Weekly'),
            ('monthly', 'Monthly'),
            ('yearly', 'Yearly'),
        ],
        blank=True,
        null=True
    )
    next_occurrence = models.DateField(null=True, blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-date', '-created_at']
    
    def __str__(self):
        return f"{self.date} - {self.category} - ${self.amount}"
    
    @property
    def yearly_cost(self):
        """Calculate yearly cost for recurring transactions"""
        if not self.is_recurring:
            return self.amount
        
        frequency_multipliers = {
            'daily': 365,
            'weekly': 52,
            'monthly': 12,
            'yearly': 1,
        }
        multiplier = frequency_multipliers.get(self.recurring_frequency, 1)
        return self.amount * Decimal(str(multiplier))

class Budget(models.Model):
    """Monthly budgets per category"""
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='budgets', null=True, blank=True)
    session_id = models.CharField(max_length=100, null=True, blank=True)
    
    category = models.ForeignKey(Category, on_delete=models.CASCADE)
    monthly_limit = models.DecimalField(max_digits=10, decimal_places=2)
    alert_threshold = models.IntegerField(default=80, help_text="Alert when spending reaches this % of limit")
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        unique_together = ['user', 'category']
        ordering = ['category__name']
    
    def __str__(self):
        return f"{self.category} - ${self.monthly_limit}/month"
    
    def get_spent_this_month(self):
        """Calculate spending for this category this month"""
        from django.db.models import Sum
        from datetime import date
        
        first_day = date.today().replace(day=1)
        
        spent = Transaction.objects.filter(
            user=self.user,
            category=self.category,
            date__gte=first_day
        ).aggregate(total=Sum('amount'))['total'] or Decimal('0')
        
        return spent
    
    @property
    def spent_percentage(self):
        """Percentage of budget spent"""
        spent = self.get_spent_this_month()
        if self.monthly_limit == 0:
            return 0
        return (spent / self.monthly_limit) * 100
    
    @property
    def is_over_threshold(self):
        """Check if spending is over alert threshold"""
        return self.spent_percentage >= self.alert_threshold

class FinancialGoal(models.Model):
    """Savings goals"""
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='goals', null=True, blank=True)
    session_id = models.CharField(max_length=100, null=True, blank=True)
    
    name = models.CharField(max_length=100)
    target_amount = models.DecimalField(max_digits=10, decimal_places=2)
    current_amount = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    target_date = models.DateField(null=True, blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['target_date']
    
    def __str__(self):
        return f"{self.name} - ${self.current_amount}/${self.target_amount}"
    
    @property
    def progress_percentage(self):
        """Progress towards goal"""
        if self.target_amount == 0:
            return 0
        return min((self.current_amount / self.target_amount) * 100, 100)
    
    @property
    def is_completed(self):
        """Check if goal is reached"""
        return self.current_amount >= self.target_amount
