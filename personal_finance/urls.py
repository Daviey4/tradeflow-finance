from django.urls import path
from . import views

app_name = 'finance'

urlpatterns = [
    # Pages
    path('', views.dashboard, name='dashboard'),
    path('transactions/', views.transactions, name='transactions'),
    path('budgets/', views.budgets, name='budgets'),
    path('goals/', views.goals, name='goals'),

    # API endpoints
    path('api/transactions/', views.api_transactions, name='api_transactions'),
    path('api/transactions/add/', views.api_add_transaction, name='api_add_transaction'),
    path('api/transactions/<int:pk>/delete/', views.api_delete_transaction, name='api_delete_transaction'),
    path('api/budgets/', views.api_budgets, name='api_budgets'),
    path('api/budgets/add/', views.api_add_budget, name='api_add_budget'),
    path('api/budgets/<int:pk>/delete/', views.api_delete_budget, name='api_delete_budget'),
    path('api/goals/', views.api_goals, name='api_goals'),
    path('api/goals/add/', views.api_add_goal, name='api_add_goal'),
    path('api/goals/<int:pk>/update/', views.api_update_goal, name='api_update_goal'),
    path('api/goals/<int:pk>/delete/', views.api_delete_goal, name='api_delete_goal'),
    path('api/categories/', views.api_categories, name='api_categories'),
    path('api/summary/', views.api_summary, name='api_summary'),
]
