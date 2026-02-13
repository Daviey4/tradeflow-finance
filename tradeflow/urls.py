"""
URL configuration for TradeFlow project.
"""
from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('trading.urls')),
    path('finance/', include('personal_finance.urls')),
]