from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.db.models import Sum, Count
from datetime import date, timedelta
from decimal import Decimal
import json

from .models import Category, Transaction, Budget, FinancialGoal


# ─────────────────────────────────────
# HELPER: Get user or session identifier
# ─────────────────────────────────────
def get_user_filter(request):
    """Get filter based on logged in user or session"""
    if request.user.is_authenticated:
        return {'user': request.user}
    else:
        session_id = request.session.session_key
        if not session_id:
            request.session.create()
            session_id = request.session.session_key
        return {'session_id': session_id}


def get_user_kwargs(request):
    """Get kwargs for creating objects"""
    if request.user.is_authenticated:
        return {'user': request.user}
    else:
        session_id = request.session.session_key
        if not session_id:
            request.session.create()
            session_id = request.session.session_key
        return {'session_id': session_id}


# ─────────────────────────────────────
# PAGE VIEWS
# ─────────────────────────────────────
def dashboard(request):
    """Personal Finance Dashboard"""
    user_filter = get_user_filter(request)
    categories = Category.objects.all()
    transactions = Transaction.objects.filter(**user_filter)[:10]
    budgets = Budget.objects.filter(**user_filter)
    goals = FinancialGoal.objects.filter(**user_filter)

    # Summary stats
    today = date.today()
    first_day = today.replace(day=1)
    monthly_spending = Transaction.objects.filter(
        **user_filter,
        date__gte=first_day
    ).aggregate(total=Sum('amount'))['total'] or Decimal('0')

    context = {
        'categories': categories,
        'transactions': transactions,
        'budgets': budgets,
        'goals': goals,
        'monthly_spending': monthly_spending,
    }
    return render(request, 'personal_finance/dashboard.html', context)


def transactions(request):
    """Transactions page"""
    user_filter = get_user_filter(request)
    all_transactions = Transaction.objects.filter(**user_filter)
    categories = Category.objects.all()
    context = {
        'transactions': all_transactions,
        'categories': categories,
    }
    return render(request, 'personal_finance/transactions.html', context)


def budgets(request):
    """Budgets page"""
    user_filter = get_user_filter(request)
    all_budgets = Budget.objects.filter(**user_filter)
    categories = Category.objects.all()
    context = {
        'budgets': all_budgets,
        'categories': categories,
    }
    return render(request, 'personal_finance/budgets.html', context)


def goals(request):
    """Goals page"""
    user_filter = get_user_filter(request)
    all_goals = FinancialGoal.objects.filter(**user_filter)
    context = {
        'goals': all_goals,
    }
    return render(request, 'personal_finance/goals.html', context)


# ─────────────────────────────────────
# API VIEWS
# ─────────────────────────────────────

# --- Categories ---
def api_categories(request):
    """Get all categories"""
    categories = Category.objects.all().values('id', 'name', 'icon', 'color')
    return JsonResponse(list(categories), safe=False)


# --- Transactions ---
def api_transactions(request):
    """Get all transactions"""
    user_filter = get_user_filter(request)
    transactions = Transaction.objects.filter(**user_filter).values(
        'id', 'amount', 'description', 'date',
        'is_recurring', 'recurring_frequency',
        'category__name', 'category__icon', 'category__color'
    )
    return JsonResponse(list(transactions), safe=False)


@csrf_exempt
@require_http_methods(["POST"])
def api_add_transaction(request):
    """Add a new transaction"""
    try:
        data = json.loads(request.body)
        user_kwargs = get_user_kwargs(request)

        transaction = Transaction.objects.create(
            **user_kwargs,
            amount=Decimal(str(data['amount'])),
            category_id=data['category'],
            description=data.get('description', ''),
            date=data.get('date', date.today().isoformat()),
            is_recurring=data.get('is_recurring', False),
            recurring_frequency=data.get('recurring_frequency', None),
        )

        return JsonResponse({
            'success': True,
            'id': transaction.id,
            'message': 'Transaction added'
        })
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=400)


@csrf_exempt
@require_http_methods(["DELETE"])
def api_delete_transaction(request, pk):
    """Delete a transaction"""
    try:
        user_filter = get_user_filter(request)
        transaction = Transaction.objects.get(pk=pk, **user_filter)
        transaction.delete()
        return JsonResponse({'success': True, 'message': 'Transaction deleted'})
    except Transaction.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'Not found'}, status=404)


# --- Budgets ---
def api_budgets(request):
    """Get all budgets"""
    user_filter = get_user_filter(request)
    budgets = Budget.objects.filter(**user_filter).values(
        'id', 'monthly_limit', 'alert_threshold',
        'category__name', 'category__icon', 'category__color'
    )
    # Add spent amount to each budget
    budget_list = []
    for budget in budgets:
        b = Budget.objects.get(pk=budget['id'])
        budget['spent'] = str(b.get_spent_this_month())
        budget['spent_percentage'] = float(b.spent_percentage)
        budget['is_over_threshold'] = b.is_over_threshold
        budget_list.append(budget)

    return JsonResponse(budget_list, safe=False)


@csrf_exempt
@require_http_methods(["POST"])
def api_add_budget(request):
    """Add a new budget"""
    try:
        data = json.loads(request.body)
        user_kwargs = get_user_kwargs(request)

        budget = Budget.objects.create(
            **user_kwargs,
            category_id=data['category'],
            monthly_limit=Decimal(str(data['monthly_limit'])),
            alert_threshold=data.get('alert_threshold', 80),
        )

        return JsonResponse({
            'success': True,
            'id': budget.id,
            'message': 'Budget added'
        })
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=400)


@csrf_exempt
@require_http_methods(["DELETE"])
def api_delete_budget(request, pk):
    """Delete a budget"""
    try:
        user_filter = get_user_filter(request)
        budget = Budget.objects.get(pk=pk, **user_filter)
        budget.delete()
        return JsonResponse({'success': True, 'message': 'Budget deleted'})
    except Budget.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'Not found'}, status=404)


# --- Goals ---
def api_goals(request):
    """Get all goals"""
    user_filter = get_user_filter(request)
    goals = FinancialGoal.objects.filter(**user_filter).values(
        'id', 'name', 'target_amount', 'current_amount', 'target_date'
    )
    # Add computed fields
    goal_list = []
    for goal in goals:
        g = FinancialGoal.objects.get(pk=goal['id'])
        goal['progress_percentage'] = float(g.progress_percentage)
        goal['is_completed'] = g.is_completed
        goal_list.append(goal)

    return JsonResponse(goal_list, safe=False)


@csrf_exempt
@require_http_methods(["POST"])
def api_add_goal(request):
    """Add a new goal"""
    try:
        data = json.loads(request.body)
        user_kwargs = get_user_kwargs(request)

        goal = FinancialGoal.objects.create(
            **user_kwargs,
            name=data['name'],
            target_amount=Decimal(str(data['target_amount'])),
            current_amount=Decimal(str(data.get('current_amount', 0))),
            target_date=data.get('target_date', None),
        )

        return JsonResponse({
            'success': True,
            'id': goal.id,
            'message': 'Goal added'
        })
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=400)


@csrf_exempt
@require_http_methods(["PATCH"])
def api_update_goal(request, pk):
    """Update goal progress"""
    try:
        data = json.loads(request.body)
        user_filter = get_user_filter(request)
        goal = FinancialGoal.objects.get(pk=pk, **user_filter)

        if 'current_amount' in data:
            goal.current_amount = Decimal(str(data['current_amount']))
        if 'name' in data:
            goal.name = data['name']
        if 'target_amount' in data:
            goal.target_amount = Decimal(str(data['target_amount']))

        goal.save()
        return JsonResponse({
            'success': True,
            'message': 'Goal updated',
            'progress': float(goal.progress_percentage)
        })
    except FinancialGoal.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'Not found'}, status=404)


@csrf_exempt
@require_http_methods(["DELETE"])
def api_delete_goal(request, pk):
    """Delete a goal"""
    try:
        user_filter = get_user_filter(request)
        goal = FinancialGoal.objects.get(pk=pk, **user_filter)
        goal.delete()
        return JsonResponse({'success': True, 'message': 'Goal deleted'})
    except FinancialGoal.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'Not found'}, status=404)


# --- Summary ---
def api_summary(request):
    """Get financial summary"""
    user_filter = get_user_filter(request)
    today = date.today()
    first_day = today.replace(day=1)

    # Monthly spending
    monthly_spending = Transaction.objects.filter(
        **user_filter,
        date__gte=first_day
    ).aggregate(total=Sum('amount'))['total'] or Decimal('0')

    # Spending by category
    by_category = Transaction.objects.filter(
        **user_filter,
        date__gte=first_day
    ).values(
        'category__name', 'category__icon', 'category__color'
    ).annotate(total=Sum('amount'))

    # Total goals progress
    goals = FinancialGoal.objects.filter(**user_filter)
    total_goal_target = sum(g.target_amount for g in goals)
    total_goal_current = sum(g.current_amount for g in goals)

    # Recurring monthly cost
    recurring = Transaction.objects.filter(
        **user_filter,
        is_recurring=True,
        recurring_frequency='monthly'
    ).aggregate(total=Sum('amount'))['total'] or Decimal('0')

    return JsonResponse({
        'monthly_spending': str(monthly_spending),
        'by_category': list(by_category),
        'total_goal_target': str(total_goal_target),
        'total_goal_current': str(total_goal_current),
        'recurring_monthly': str(recurring),
    })
