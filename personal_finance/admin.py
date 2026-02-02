from django.contrib import admin
from .models import Category, Transaction, Budget, FinancialGoal

@admin.register(Category)
class CategoryAdmin(admin.ModelAdmin):
    list_display = ['icon', 'name', 'color']
    search_fields = ['name']

@admin.register(Transaction)
class TransactionAdmin(admin.ModelAdmin):
    list_display = ['date', 'category', 'amount', 'description', 'is_recurring']
    list_filter = ['category', 'is_recurring', 'date']
    search_fields = ['description']
    date_hierarchy = 'date'

@admin.register(Budget)
class BudgetAdmin(admin.ModelAdmin):
    list_display = ['category', 'monthly_limit', 'alert_threshold', 'spent_percentage']
    list_filter = ['category']

@admin.register(FinancialGoal)
class FinancialGoalAdmin(admin.ModelAdmin):
    list_display = ['name', 'current_amount', 'target_amount', 'progress_percentage', 'target_date']
    list_filter = ['target_date']
    search_fields = ['name']
