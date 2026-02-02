import json
import requests
from decimal import Decimal
from django.shortcuts import render, redirect
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
from django.utils import timezone
from django.conf import settings
from .models import Portfolio, Holding, Trade, TradingStrategy, Notification, PriceHistory


# Supported assets
ASSETS = [
    {'id': 'bitcoin', 'name': 'Bitcoin', 'symbol': 'BTC', 'color': '#F7931A'},
    {'id': 'ethereum', 'name': 'Ethereum', 'symbol': 'ETH', 'color': '#627EEA'},
    {'id': 'solana', 'name': 'Solana', 'symbol': 'SOL', 'color': '#00FFA3'},
    {'id': 'dogecoin', 'name': 'Dogecoin', 'symbol': 'DOGE', 'color': '#C2A633'},
    {'id': 'cardano', 'name': 'Cardano', 'symbol': 'ADA', 'color': '#0033AD'},
    {'id': 'ripple', 'name': 'XRP', 'symbol': 'XRP', 'color': '#23292F'},
]


def get_or_create_portfolio(request):
    """Get or create portfolio for session"""
    session_id = request.session.session_key
    if not session_id:
        request.session.create()
        session_id = request.session.session_key
    
    portfolio, created = Portfolio.objects.get_or_create(
        session_id=session_id,
        defaults={'balance': Decimal('50000.00')}
    )
    return portfolio


def fetch_price(asset_id):
    """Fetch current price from CoinGecko API"""
    try:
        url = f"{settings.COINGECKO_API_URL}/simple/price"
        params = {
            'ids': asset_id,
            'vs_currencies': 'usd',
            'include_24hr_change': 'true'
        }
        response = requests.get(url, params=params, timeout=10)
        response.raise_for_status()
        data = response.json()
        
        if asset_id in data:
            return {
                'price': Decimal(str(data[asset_id]['usd'])),
                'change_24h': data[asset_id].get('usd_24h_change', 0),
                'status': 'connected'
            }
    except Exception as e:
        print(f"Price fetch error: {e}")
    
    return {'price': None, 'change_24h': 0, 'status': 'error'}


def dashboard(request):
    """Main dashboard view"""
    portfolio = get_or_create_portfolio(request)
    selected_asset = request.GET.get('asset', 'bitcoin')
    
    # Get or create strategy for this asset
    asset_info = next((a for a in ASSETS if a['id'] == selected_asset), ASSETS[0])
    strategy, _ = TradingStrategy.objects.get_or_create(
        portfolio=portfolio,
        asset_id=selected_asset,
        defaults={
            'symbol': asset_info['symbol'],
            'strategy_type': 'threshold',
            'trade_amount': Decimal('0.01'),
        }
    )
    
    # Get holdings
    holding, _ = Holding.objects.get_or_create(
        portfolio=portfolio,
        asset_id=selected_asset,
        defaults={'symbol': asset_info['symbol'], 'amount': 0, 'average_cost': 0}
    )
    
    # Get recent trades
    recent_trades = Trade.objects.filter(portfolio=portfolio)[:10]
    
    # Get notifications
    notifications = Notification.objects.filter(portfolio=portfolio)[:20]
    
    # Calculate stats
    all_trades = Trade.objects.filter(portfolio=portfolio)
    total_trades = all_trades.count()
    winning_trades = all_trades.filter(profit__gt=0).count()
    sell_trades = all_trades.filter(trade_type='SELL').count()
    win_rate = (winning_trades / sell_trades * 100) if sell_trades > 0 else 0
    total_realized_pl = sum(t.profit or 0 for t in all_trades.filter(profit__isnull=False))
    
    context = {
        'portfolio': portfolio,
        'assets': ASSETS,
        'selected_asset': selected_asset,
        'asset_info': asset_info,
        'strategy': strategy,
        'holding': holding,
        'recent_trades': recent_trades,
        'notifications': notifications,
        'total_trades': total_trades,
        'win_rate': round(win_rate, 1),
        'total_realized_pl': total_realized_pl,
    }
    
    return render(request, 'trading/dashboard.html', context)


def trades_view(request):
    """Trades history view"""
    portfolio = get_or_create_portfolio(request)
    trades = Trade.objects.filter(portfolio=portfolio)
    total_realized_pl = sum(t.profit or 0 for t in trades.filter(profit__isnull=False))
    
    context = {
        'portfolio': portfolio,
        'trades': trades,
        'total_realized_pl': total_realized_pl,
    }
    return render(request, 'trading/trades.html', context)


def alerts_view(request):
    """Alerts/notifications view"""
    portfolio = get_or_create_portfolio(request)
    notifications = Notification.objects.filter(portfolio=portfolio)
    
    context = {
        'portfolio': portfolio,
        'notifications': notifications,
    }
    return render(request, 'trading/alerts.html', context)


def calculator_view(request):
    """Investment calculator view"""
    portfolio = get_or_create_portfolio(request)
    
    context = {
        'portfolio': portfolio,
    }
    return render(request, 'trading/calculator.html', context)


def security_lab_view(request):
    """Security lab dashboard"""
    vulnerabilities = [
        {
            'name': 'SQL Injection',
            'endpoints': ['/vuln/login/', '/vuln/search/?q='],
            'severity': 'CRITICAL',
            'owasp': 'A03:2021 - Injection',
        },
        {
            'name': 'Cross-Site Scripting (XSS)',
            'endpoints': ['/vuln/profile/', '/vuln/comment/?message='],
            'severity': 'HIGH',
            'owasp': 'A03:2021 - Injection',
        },
        {
            'name': 'IDOR (Broken Access)',
            'endpoints': ['/vuln/portfolio/1/', '/vuln/trade/delete/1/'],
            'severity': 'HIGH',
            'owasp': 'A01:2021 - Broken Access Control',
        },
        {
            'name': 'Broken Authentication',
            'endpoints': ['/vuln/register/', '/vuln/password-reset/'],
            'severity': 'CRITICAL',
            'owasp': 'A07:2021 - Auth Failures',
        },
        {
            'name': 'Sensitive Data Exposure',
            'endpoints': ['/vuln/debug/', '/vuln/users/export/'],
            'severity': 'CRITICAL',
            'owasp': 'A02:2021 - Crypto Failures',
        },
        {
            'name': 'Security Misconfiguration',
            'endpoints': ['/vuln/upload/', '/vuln/redirect/?url='],
            'severity': 'MEDIUM',
            'owasp': 'A05:2021 - Misconfiguration',
        },
        {
            'name': 'SSRF',
            'endpoints': ['/vuln/fetch/?url='],
            'severity': 'HIGH',
            'owasp': 'A10:2021 - SSRF',
        },
        {
            'name': 'Command Injection',
            'endpoints': ['/vuln/ping/?host=', '/vuln/backup/?filename='],
            'severity': 'CRITICAL',
            'owasp': 'A03:2021 - Injection',
        },
    ]
    
    return render(request, 'trading/security_lab.html', {'vulnerabilities': vulnerabilities})


@require_http_methods(["GET"])
def api_price(request, asset_id):
    """API endpoint to get current price"""
    price_data = fetch_price(asset_id)
    
    # Store price history
    if price_data['price']:
        PriceHistory.objects.create(
            asset_id=asset_id,
            price=price_data['price']
        )
        # Clean old history (keep last 500)
        old_records = PriceHistory.objects.filter(asset_id=asset_id)[500:]
        if old_records.exists():
            PriceHistory.objects.filter(id__in=old_records.values_list('id', flat=True)).delete()
    
    return JsonResponse({
        'price': float(price_data['price']) if price_data['price'] else None,
        'change_24h': price_data['change_24h'],
        'status': price_data['status'],
        'timestamp': timezone.now().isoformat()
    })


@require_http_methods(["GET"])
def api_price_history(request, asset_id):
    """API endpoint to get price history"""
    limit = int(request.GET.get('limit', 100))
    history = PriceHistory.objects.filter(asset_id=asset_id)[:limit]
    
    return JsonResponse({
        'history': [
            {'price': float(h.price), 'timestamp': h.timestamp.isoformat()}
            for h in reversed(list(history))
        ]
    })


@require_http_methods(["GET"])
def api_portfolio(request):
    """API endpoint to get portfolio data"""
    portfolio = get_or_create_portfolio(request)
    asset_id = request.GET.get('asset', 'bitcoin')
    
    holding = Holding.objects.filter(portfolio=portfolio, asset_id=asset_id).first()
    strategy = TradingStrategy.objects.filter(portfolio=portfolio, asset_id=asset_id).first()
    
    return JsonResponse({
        'balance': float(portfolio.balance),
        'holding': {
            'amount': float(holding.amount) if holding else 0,
            'average_cost': float(holding.average_cost) if holding else 0,
        } if holding else None,
        'strategy': {
            'type': strategy.strategy_type if strategy else 'threshold',
            'is_active': strategy.is_active if strategy else False,
            'buy_threshold': float(strategy.buy_threshold) if strategy else 0,
            'sell_threshold': float(strategy.sell_threshold) if strategy else 0,
            'trade_amount': float(strategy.trade_amount) if strategy else 0.01,
            'trailing_percent': float(strategy.trailing_percent) if strategy else 5,
            'dca_interval': strategy.dca_interval if strategy else 60,
            'dca_amount': float(strategy.dca_amount) if strategy else 100,
        } if strategy else None
    })


@csrf_exempt
@require_http_methods(["POST"])
def api_trade(request):
    """API endpoint to execute a trade"""
    try:
        data = json.loads(request.body)
        portfolio = get_or_create_portfolio(request)
        
        trade_type = data.get('type', '').upper()
        asset_id = data.get('asset_id')
        amount = Decimal(str(data.get('amount', 0)))
        price = Decimal(str(data.get('price', 0)))
        reason = data.get('reason', 'Manual trade')
        
        asset_info = next((a for a in ASSETS if a['id'] == asset_id), None)
        if not asset_info:
            return JsonResponse({'success': False, 'error': 'Invalid asset'}, status=400)
        
        holding, _ = Holding.objects.get_or_create(
            portfolio=portfolio,
            asset_id=asset_id,
            defaults={'symbol': asset_info['symbol'], 'amount': 0, 'average_cost': 0}
        )
        
        total = amount * price
        profit = None
        
        if trade_type == 'BUY':
            if portfolio.balance < total:
                return JsonResponse({'success': False, 'error': 'Insufficient balance'}, status=400)
            
            # Update average cost
            if holding.amount > 0:
                new_total_cost = (holding.average_cost * holding.amount) + total
                new_amount = holding.amount + amount
                holding.average_cost = new_total_cost / new_amount
            else:
                holding.average_cost = price
            
            holding.amount += amount
            portfolio.balance -= total
            
        elif trade_type == 'SELL':
            if holding.amount < amount:
                return JsonResponse({'success': False, 'error': 'Insufficient holdings'}, status=400)
            
            profit = (price - holding.average_cost) * amount
            holding.amount -= amount
            portfolio.balance += total
            
        else:
            return JsonResponse({'success': False, 'error': 'Invalid trade type'}, status=400)
        
        holding.save()
        portfolio.save()
        
        # Create trade record
        trade = Trade.objects.create(
            portfolio=portfolio,
            trade_type=trade_type,
            asset_id=asset_id,
            symbol=asset_info['symbol'],
            amount=amount,
            price=price,
            total=total,
            profit=profit,
            reason=reason
        )
        
        # Create notification
        if trade_type == 'BUY':
            message = f"Bought {amount:.6f} {asset_info['symbol']} @ ${price:,.2f}"
        else:
            profit_str = f" ({'+' if profit >= 0 else ''}{profit:.2f})"
            message = f"Sold {amount:.6f} {asset_info['symbol']} @ ${price:,.2f}{profit_str}"
        
        Notification.objects.create(
            portfolio=portfolio,
            notification_type=trade_type.lower(),
            message=message
        )
        
        return JsonResponse({
            'success': True,
            'trade': {
                'id': trade.id,
                'type': trade.trade_type,
                'amount': float(trade.amount),
                'price': float(trade.price),
                'total': float(trade.total),
                'profit': float(trade.profit) if trade.profit else None,
            },
            'balance': float(portfolio.balance),
            'holding': float(holding.amount),
            'average_cost': float(holding.average_cost)
        })
        
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=500)


@csrf_exempt
@require_http_methods(["POST"])
def api_strategy(request):
    """API endpoint to update strategy settings"""
    try:
        data = json.loads(request.body)
        portfolio = get_or_create_portfolio(request)
        asset_id = data.get('asset_id')
        
        asset_info = next((a for a in ASSETS if a['id'] == asset_id), None)
        if not asset_info:
            return JsonResponse({'success': False, 'error': 'Invalid asset'}, status=400)
        
        strategy, _ = TradingStrategy.objects.get_or_create(
            portfolio=portfolio,
            asset_id=asset_id,
            defaults={'symbol': asset_info['symbol']}
        )
        
        # Update fields
        if 'strategy_type' in data:
            strategy.strategy_type = data['strategy_type']
        if 'is_active' in data:
            strategy.is_active = data['is_active']
            # Add notification
            status = 'started' if data['is_active'] else 'stopped'
            Notification.objects.create(
                portfolio=portfolio,
                notification_type='system',
                message=f"Automation {status} for {asset_info['symbol']} ({strategy.strategy_type})"
            )
        if 'buy_threshold' in data:
            strategy.buy_threshold = Decimal(str(data['buy_threshold']))
        if 'sell_threshold' in data:
            strategy.sell_threshold = Decimal(str(data['sell_threshold']))
        if 'trade_amount' in data:
            strategy.trade_amount = Decimal(str(data['trade_amount']))
        if 'trailing_percent' in data:
            strategy.trailing_percent = Decimal(str(data['trailing_percent']))
        if 'highest_price' in data:
            strategy.highest_price = Decimal(str(data['highest_price']))
        if 'lowest_price' in data:
            strategy.lowest_price = Decimal(str(data['lowest_price'])) if data['lowest_price'] else None
        if 'trailing_stop_price' in data:
            strategy.trailing_stop_price = Decimal(str(data['trailing_stop_price']))
        if 'trailing_buy_price' in data:
            strategy.trailing_buy_price = Decimal(str(data['trailing_buy_price'])) if data['trailing_buy_price'] else None
        if 'dca_interval' in data:
            strategy.dca_interval = int(data['dca_interval'])
        if 'dca_amount' in data:
            strategy.dca_amount = Decimal(str(data['dca_amount']))
        if 'last_dca_time' in data:
            strategy.last_dca_time = timezone.now() if data['last_dca_time'] else None
        
        strategy.save()
        
        return JsonResponse({
            'success': True,
            'strategy': {
                'type': strategy.strategy_type,
                'is_active': strategy.is_active,
                'buy_threshold': float(strategy.buy_threshold),
                'sell_threshold': float(strategy.sell_threshold),
                'trade_amount': float(strategy.trade_amount),
            }
        })
        
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=500)


@csrf_exempt
@require_http_methods(["POST"])
def api_clear_notifications(request):
    """Clear all notifications"""
    portfolio = get_or_create_portfolio(request)
    Notification.objects.filter(portfolio=portfolio).delete()
    return JsonResponse({'success': True})


@csrf_exempt
@require_http_methods(["POST"])
def api_reset_portfolio(request):
    """Reset portfolio to initial state"""
    portfolio = get_or_create_portfolio(request)
    
    # Reset balance
    portfolio.balance = Decimal('50000.00')
    portfolio.save()
    
    # Clear holdings
    Holding.objects.filter(portfolio=portfolio).delete()
    
    # Clear trades
    Trade.objects.filter(portfolio=portfolio).delete()
    
    # Clear strategies
    TradingStrategy.objects.filter(portfolio=portfolio).delete()
    
    # Add notification
    Notification.objects.create(
        portfolio=portfolio,
        notification_type='system',
        message='Portfolio reset to initial state ($50,000)'
    )
    
    return JsonResponse({'success': True})
