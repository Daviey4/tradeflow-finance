"""
Alpaca API Views for TradeFlow

These views connect the Django app to real Alpaca trading.
"""

import json
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import render

from .alpaca_trading import AlpacaTrader, AutoTrader, ALPACA_AVAILABLE


def get_trader():
    """Get Alpaca trader instance"""
    if not ALPACA_AVAILABLE:
        return None
    try:
        return AlpacaTrader(paper=True)  # Use paper trading by default
    except Exception:
        return None


def alpaca_dashboard(request):
    """Alpaca trading dashboard"""
    trader = get_trader()
    
    context = {
        'alpaca_available': ALPACA_AVAILABLE,
        'alpaca_connected': trader is not None,
    }
    
    if trader:
        try:
            context['account'] = trader.get_account()
            context['positions'] = trader.get_positions()
        except Exception as e:
            context['error'] = str(e)
    
    return render(request, 'trading/alpaca_dashboard.html', context)


@require_http_methods(["GET"])
def api_alpaca_account(request):
    """Get Alpaca account info"""
    trader = get_trader()
    
    if not trader:
        return JsonResponse({
            'success': False,
            'error': 'Alpaca not configured. Set ALPACA_API_KEY and ALPACA_SECRET_KEY.'
        }, status=400)
    
    try:
        account = trader.get_account()
        return JsonResponse({'success': True, 'account': account})
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=500)


@require_http_methods(["GET"])
def api_alpaca_positions(request):
    """Get all positions"""
    trader = get_trader()
    
    if not trader:
        return JsonResponse({'success': False, 'error': 'Alpaca not configured'}, status=400)
    
    try:
        positions = trader.get_positions()
        return JsonResponse({'success': True, 'positions': positions})
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=500)


@require_http_methods(["GET"])
def api_alpaca_price(request, symbol):
    """Get current price for a symbol"""
    trader = get_trader()
    
    if not trader:
        return JsonResponse({'success': False, 'error': 'Alpaca not configured'}, status=400)
    
    try:
        price = trader.get_price(symbol.upper())
        if price:
            return JsonResponse({'success': True, 'price': price})
        else:
            return JsonResponse({'success': False, 'error': 'Symbol not found'}, status=404)
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=500)


@require_http_methods(["GET"])
def api_alpaca_history(request, symbol):
    """Get price history for a symbol"""
    trader = get_trader()
    
    if not trader:
        return JsonResponse({'success': False, 'error': 'Alpaca not configured'}, status=400)
    
    days = int(request.GET.get('days', 30))
    
    try:
        history = trader.get_price_history(symbol.upper(), days=days)
        return JsonResponse({'success': True, 'history': history})
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=500)


@csrf_exempt
@require_http_methods(["POST"])
def api_alpaca_buy(request):
    """Buy stock"""
    trader = get_trader()
    
    if not trader:
        return JsonResponse({'success': False, 'error': 'Alpaca not configured'}, status=400)
    
    try:
        data = json.loads(request.body)
        symbol = data.get('symbol', '').upper()
        quantity = data.get('quantity')
        dollars = data.get('dollars')
        limit_price = data.get('limit_price')
        
        if not symbol:
            return JsonResponse({'success': False, 'error': 'Symbol required'}, status=400)
        
        if quantity:
            order = trader.buy(symbol, quantity=float(quantity), limit_price=limit_price)
        elif dollars:
            order = trader.buy(symbol, dollars=float(dollars))
        else:
            return JsonResponse({'success': False, 'error': 'Quantity or dollars required'}, status=400)
        
        return JsonResponse({'success': True, 'order': order})
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=500)


@csrf_exempt
@require_http_methods(["POST"])
def api_alpaca_sell(request):
    """Sell stock"""
    trader = get_trader()
    
    if not trader:
        return JsonResponse({'success': False, 'error': 'Alpaca not configured'}, status=400)
    
    try:
        data = json.loads(request.body)
        symbol = data.get('symbol', '').upper()
        quantity = data.get('quantity')
        dollars = data.get('dollars')
        limit_price = data.get('limit_price')
        
        if not symbol:
            return JsonResponse({'success': False, 'error': 'Symbol required'}, status=400)
        
        if quantity:
            order = trader.sell(symbol, quantity=float(quantity), limit_price=limit_price)
        elif dollars:
            order = trader.sell(symbol, dollars=float(dollars))
        else:
            return JsonResponse({'success': False, 'error': 'Quantity or dollars required'}, status=400)
        
        return JsonResponse({'success': True, 'order': order})
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=500)


@require_http_methods(["GET"])
def api_alpaca_orders(request):
    """Get orders"""
    trader = get_trader()
    
    if not trader:
        return JsonResponse({'success': False, 'error': 'Alpaca not configured'}, status=400)
    
    try:
        status = request.GET.get('status', 'all')
        orders = trader.get_orders(status=status)
        return JsonResponse({'success': True, 'orders': orders})
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=500)
