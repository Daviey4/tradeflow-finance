/**
 * TradeFlow Mobile App
 * React Native application for iOS and Android
 * 
 * To create this project:
 * npx react-native init TradeFlowMobile
 * cd TradeFlowMobile
 * npm install @react-navigation/native @react-navigation/bottom-tabs
 * npm install react-native-screens react-native-safe-area-context
 * npm install axios react-native-chart-kit react-native-svg
 * npm install @react-native-async-storage/async-storage
 */

import React, { useState, useEffect, useCallback } from 'react';
import {
  SafeAreaView,
  ScrollView,
  View,
  Text,
  TextInput,
  TouchableOpacity,
  StyleSheet,
  Dimensions,
  RefreshControl,
  Alert,
  StatusBar,
} from 'react-native';
import { NavigationContainer } from '@react-navigation/native';
import { createBottomTabNavigator } from '@react-navigation/bottom-tabs';
import AsyncStorage from '@react-native-async-storage/async-storage';

// API Configuration - Change this to your deployed server
const API_BASE_URL = 'https://your-tradeflow-server.com'; // or http://localhost:8000 for development
const COINGECKO_API = 'https://api.coingecko.com/api/v3';

// Colors
const colors = {
  background: '#000000',
  card: '#18181b',
  cardBorder: '#27272a',
  primary: '#22c55e',
  danger: '#ef4444',
  warning: '#f59e0b',
  text: '#ffffff',
  textMuted: '#71717a',
  accent: '#06b6d4',
};

const { width } = Dimensions.get('window');

// ============================================================
// API Service
// ============================================================
const api = {
  async getPrice(assetId) {
    try {
      const response = await fetch(
        `${COINGECKO_API}/simple/price?ids=${assetId}&vs_currencies=usd&include_24hr_change=true`
      );
      const data = await response.json();
      return {
        price: data[assetId]?.usd,
        change24h: data[assetId]?.usd_24h_change || 0,
      };
    } catch (error) {
      console.error('Price fetch error:', error);
      return null;
    }
  },

  async getPortfolio() {
    try {
      const portfolio = await AsyncStorage.getItem('portfolio');
      return portfolio ? JSON.parse(portfolio) : {
        balance: 50000,
        holdings: {},
        averageCosts: {},
      };
    } catch (error) {
      return { balance: 50000, holdings: {}, averageCosts: {} };
    }
  },

  async savePortfolio(portfolio) {
    await AsyncStorage.setItem('portfolio', JSON.stringify(portfolio));
  },

  async getTrades() {
    try {
      const trades = await AsyncStorage.getItem('trades');
      return trades ? JSON.parse(trades) : [];
    } catch (error) {
      return [];
    }
  },

  async saveTrade(trade) {
    const trades = await this.getTrades();
    trades.unshift(trade);
    await AsyncStorage.setItem('trades', JSON.stringify(trades.slice(0, 100)));
  },
};

// ============================================================
// Dashboard Screen
// ============================================================
function DashboardScreen() {
  const [price, setPrice] = useState(null);
  const [change24h, setChange24h] = useState(0);
  const [portfolio, setPortfolio] = useState({ balance: 50000, holdings: {}, averageCosts: {} });
  const [selectedAsset, setSelectedAsset] = useState('bitcoin');
  const [isLoading, setIsLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  
  // Strategy state
  const [strategy, setStrategy] = useState('threshold');
  const [isRunning, setIsRunning] = useState(false);
  const [buyThreshold, setBuyThreshold] = useState('');
  const [sellThreshold, setSellThreshold] = useState('');
  const [tradeAmount, setTradeAmount] = useState('0.01');

  const assets = [
    { id: 'bitcoin', symbol: 'BTC', name: 'Bitcoin', color: '#F7931A' },
    { id: 'ethereum', symbol: 'ETH', name: 'Ethereum', color: '#627EEA' },
    { id: 'solana', symbol: 'SOL', name: 'Solana', color: '#00FFA3' },
  ];

  const currentAsset = assets.find(a => a.id === selectedAsset);
  const currentHoldings = portfolio.holdings[selectedAsset] || 0;
  const currentAvgCost = portfolio.averageCosts[selectedAsset] || 0;
  const holdingsValue = currentHoldings * (price || 0);
  const unrealizedPL = currentHoldings > 0 ? (price - currentAvgCost) * currentHoldings : 0;
  const portfolioValue = portfolio.balance + holdingsValue;
  const totalProfit = portfolioValue - 50000;

  const fetchData = useCallback(async () => {
    const priceData = await api.getPrice(selectedAsset);
    if (priceData) {
      setPrice(priceData.price);
      setChange24h(priceData.change24h);
      
      // Initialize thresholds
      if (!buyThreshold) {
        setBuyThreshold(Math.round(priceData.price * 0.97).toString());
        setSellThreshold(Math.round(priceData.price * 1.03).toString());
      }
    }
    
    const portfolioData = await api.getPortfolio();
    setPortfolio(portfolioData);
    setIsLoading(false);
  }, [selectedAsset, buyThreshold]);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 10000);
    return () => clearInterval(interval);
  }, [fetchData]);

  // Trading automation
  useEffect(() => {
    if (!isRunning || !price) return;

    const checkTrade = async () => {
      const buyPrice = parseFloat(buyThreshold);
      const sellPrice = parseFloat(sellThreshold);
      const amount = parseFloat(tradeAmount);

      if (strategy === 'threshold') {
        // Buy logic
        if (price <= buyPrice && portfolio.balance >= price * amount) {
          await executeTrade('buy', amount, 'Auto: Price hit buy threshold');
        }
        // Sell logic
        if (price >= sellPrice && currentHoldings >= amount) {
          await executeTrade('sell', amount, 'Auto: Price hit sell threshold');
        }
      }
    };

    checkTrade();
  }, [price, isRunning, strategy, buyThreshold, sellThreshold]);

  const executeTrade = async (type, amount, reason) => {
    const newPortfolio = { ...portfolio };
    const cost = price * amount;

    if (type === 'buy') {
      if (newPortfolio.balance < cost) {
        Alert.alert('Error', 'Insufficient balance');
        return;
      }

      const currentHold = newPortfolio.holdings[selectedAsset] || 0;
      const currentCost = newPortfolio.averageCosts[selectedAsset] || 0;
      const newHoldings = currentHold + amount;
      const newAvgCost = currentHold > 0 
        ? ((currentCost * currentHold) + cost) / newHoldings 
        : price;

      newPortfolio.balance -= cost;
      newPortfolio.holdings[selectedAsset] = newHoldings;
      newPortfolio.averageCosts[selectedAsset] = newAvgCost;
    } else {
      const currentHold = newPortfolio.holdings[selectedAsset] || 0;
      if (currentHold < amount) {
        Alert.alert('Error', 'Insufficient holdings');
        return;
      }

      const avgCost = newPortfolio.averageCosts[selectedAsset] || 0;
      const profit = (price - avgCost) * amount;

      newPortfolio.balance += cost;
      newPortfolio.holdings[selectedAsset] = currentHold - amount;

      await api.saveTrade({
        type: 'SELL',
        asset: selectedAsset,
        symbol: currentAsset.symbol,
        amount,
        price,
        total: cost,
        profit,
        reason,
        time: new Date().toISOString(),
      });
    }

    if (type === 'buy') {
      await api.saveTrade({
        type: 'BUY',
        asset: selectedAsset,
        symbol: currentAsset.symbol,
        amount,
        price,
        total: cost,
        reason,
        time: new Date().toISOString(),
      });
    }

    await api.savePortfolio(newPortfolio);
    setPortfolio(newPortfolio);
  };

  const onRefresh = async () => {
    setRefreshing(true);
    await fetchData();
    setRefreshing(false);
  };

  if (isLoading) {
    return (
      <View style={styles.loadingContainer}>
        <Text style={styles.loadingText}>Loading TradeFlow...</Text>
      </View>
    );
  }

  return (
    <SafeAreaView style={styles.container}>
      <StatusBar barStyle="light-content" />
      <ScrollView
        refreshControl={<RefreshControl refreshing={refreshing} onRefresh={onRefresh} tintColor={colors.primary} />}
        showsVerticalScrollIndicator={false}
      >
        {/* Header */}
        <View style={styles.header}>
          <Text style={styles.headerTitle}>TradeFlow</Text>
          <View style={[styles.statusBadge, { backgroundColor: price ? colors.primary + '20' : colors.danger + '20' }]}>
            <View style={[styles.statusDot, { backgroundColor: price ? colors.primary : colors.danger }]} />
            <Text style={[styles.statusText, { color: price ? colors.primary : colors.danger }]}>
              {price ? 'Live' : 'Offline'}
            </Text>
          </View>
        </View>

        {/* Portfolio Stats */}
        <View style={styles.statsRow}>
          <View style={styles.statCard}>
            <Text style={styles.statLabel}>Portfolio Value</Text>
            <Text style={styles.statValue}>${portfolioValue.toLocaleString(undefined, { maximumFractionDigits: 2 })}</Text>
          </View>
          <View style={styles.statCard}>
            <Text style={styles.statLabel}>Total P/L</Text>
            <Text style={[styles.statValue, { color: totalProfit >= 0 ? colors.primary : colors.danger }]}>
              {totalProfit >= 0 ? '+' : ''}${totalProfit.toFixed(2)}
            </Text>
          </View>
        </View>

        {/* Asset Selector */}
        <View style={styles.assetSelector}>
          {assets.map(asset => (
            <TouchableOpacity
              key={asset.id}
              style={[
                styles.assetButton,
                selectedAsset === asset.id && styles.assetButtonActive
              ]}
              onPress={() => {
                setSelectedAsset(asset.id);
                setBuyThreshold('');
                setSellThreshold('');
              }}
            >
              <Text style={[
                styles.assetButtonText,
                selectedAsset === asset.id && styles.assetButtonTextActive
              ]}>
                {asset.symbol}
              </Text>
            </TouchableOpacity>
          ))}
        </View>

        {/* Price Display */}
        <View style={styles.priceCard}>
          <View style={styles.priceHeader}>
            <View>
              <Text style={styles.assetName}>{currentAsset?.name}</Text>
              <Text style={styles.assetSymbol}>{currentAsset?.symbol}</Text>
            </View>
            <View style={styles.priceRight}>
              <Text style={styles.priceValue}>
                ${price?.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 }) || '---'}
              </Text>
              <Text style={[styles.priceChange, { color: change24h >= 0 ? colors.primary : colors.danger }]}>
                {change24h >= 0 ? '↑' : '↓'} {Math.abs(change24h).toFixed(2)}%
              </Text>
            </View>
          </View>
        </View>

        {/* Holdings */}
        <View style={styles.card}>
          <Text style={styles.cardTitle}>Your Holdings</Text>
          <View style={styles.holdingRow}>
            <Text style={styles.holdingLabel}>{currentAsset?.symbol}</Text>
            <Text style={styles.holdingValue}>{currentHoldings.toFixed(6)}</Text>
          </View>
          <View style={styles.holdingRow}>
            <Text style={styles.holdingLabel}>Value</Text>
            <Text style={styles.holdingValue}>${holdingsValue.toFixed(2)}</Text>
          </View>
          <View style={styles.holdingRow}>
            <Text style={styles.holdingLabel}>Avg Cost</Text>
            <Text style={styles.holdingValue}>${currentAvgCost.toFixed(2)}</Text>
          </View>
          <View style={styles.divider} />
          <View style={styles.holdingRow}>
            <Text style={styles.holdingLabel}>Unrealized P/L</Text>
            <Text style={[styles.holdingValue, { color: unrealizedPL >= 0 ? colors.primary : colors.danger }]}>
              {unrealizedPL >= 0 ? '+' : ''}${unrealizedPL.toFixed(2)}
            </Text>
          </View>
        </View>

        {/* Strategy Settings */}
        <View style={styles.card}>
          <Text style={styles.cardTitle}>Automation</Text>
          
          {/* Strategy Buttons */}
          <View style={styles.strategyRow}>
            {['threshold', 'dca'].map(s => (
              <TouchableOpacity
                key={s}
                style={[styles.strategyButton, strategy === s && styles.strategyButtonActive]}
                onPress={() => setStrategy(s)}
              >
                <Text style={[styles.strategyButtonText, strategy === s && styles.strategyButtonTextActive]}>
                  {s === 'threshold' ? '📊 Threshold' : '💰 DCA'}
                </Text>
              </TouchableOpacity>
            ))}
          </View>

          {strategy === 'threshold' && (
            <>
              <View style={styles.inputRow}>
                <View style={styles.inputGroup}>
                  <Text style={styles.inputLabel}>Buy Below</Text>
                  <TextInput
                    style={[styles.input, { color: colors.primary }]}
                    value={buyThreshold}
                    onChangeText={setBuyThreshold}
                    keyboardType="numeric"
                    placeholderTextColor={colors.textMuted}
                  />
                </View>
                <View style={styles.inputGroup}>
                  <Text style={styles.inputLabel}>Sell Above</Text>
                  <TextInput
                    style={[styles.input, { color: colors.danger }]}
                    value={sellThreshold}
                    onChangeText={setSellThreshold}
                    keyboardType="numeric"
                    placeholderTextColor={colors.textMuted}
                  />
                </View>
              </View>
              <View style={styles.inputGroup}>
                <Text style={styles.inputLabel}>Trade Amount ({currentAsset?.symbol})</Text>
                <TextInput
                  style={styles.input}
                  value={tradeAmount}
                  onChangeText={setTradeAmount}
                  keyboardType="numeric"
                  placeholderTextColor={colors.textMuted}
                />
              </View>
            </>
          )}

          {/* Start/Stop Button */}
          <TouchableOpacity
            style={[styles.toggleButton, { backgroundColor: isRunning ? colors.danger : colors.primary }]}
            onPress={() => setIsRunning(!isRunning)}
          >
            <Text style={styles.toggleButtonText}>
              {isRunning ? '⏹ Stop Automation' : '▶ Start Automation'}
            </Text>
          </TouchableOpacity>
        </View>

        {/* Manual Trade Buttons */}
        <View style={styles.tradeButtons}>
          <TouchableOpacity
            style={[styles.tradeButton, styles.buyButton]}
            onPress={() => executeTrade('buy', parseFloat(tradeAmount), 'Manual buy')}
          >
            <Text style={styles.tradeButtonText}>Buy</Text>
          </TouchableOpacity>
          <TouchableOpacity
            style={[styles.tradeButton, styles.sellButton]}
            onPress={() => executeTrade('sell', parseFloat(tradeAmount), 'Manual sell')}
          >
            <Text style={styles.tradeButtonText}>Sell</Text>
          </TouchableOpacity>
        </View>

        <View style={{ height: 100 }} />
      </ScrollView>
    </SafeAreaView>
  );
}

// ============================================================
// Trades Screen
// ============================================================
function TradesScreen() {
  const [trades, setTrades] = useState([]);
  const [refreshing, setRefreshing] = useState(false);

  const loadTrades = async () => {
    const data = await api.getTrades();
    setTrades(data);
  };

  useEffect(() => {
    loadTrades();
  }, []);

  const onRefresh = async () => {
    setRefreshing(true);
    await loadTrades();
    setRefreshing(false);
  };

  const totalRealizedPL = trades
    .filter(t => t.profit !== undefined)
    .reduce((sum, t) => sum + t.profit, 0);

  return (
    <SafeAreaView style={styles.container}>
      <View style={styles.header}>
        <Text style={styles.headerTitle}>Trade History</Text>
        <View style={[styles.statusBadge, { backgroundColor: totalRealizedPL >= 0 ? colors.primary + '20' : colors.danger + '20' }]}>
          <Text style={[styles.statusText, { color: totalRealizedPL >= 0 ? colors.primary : colors.danger }]}>
            {totalRealizedPL >= 0 ? '+' : ''}${totalRealizedPL.toFixed(2)}
          </Text>
        </View>
      </View>

      <ScrollView
        refreshControl={<RefreshControl refreshing={refreshing} onRefresh={onRefresh} tintColor={colors.primary} />}
      >
        {trades.length === 0 ? (
          <View style={styles.emptyState}>
            <Text style={styles.emptyStateIcon}>📊</Text>
            <Text style={styles.emptyStateText}>No trades yet</Text>
          </View>
        ) : (
          trades.map((trade, index) => (
            <View key={index} style={[styles.tradeItem, { borderLeftColor: trade.type === 'BUY' ? colors.primary : colors.danger }]}>
              <View style={styles.tradeHeader}>
                <View style={styles.tradeLeft}>
                  <View style={[styles.tradeBadge, { backgroundColor: trade.type === 'BUY' ? colors.primary + '20' : colors.danger + '20' }]}>
                    <Text style={[styles.tradeBadgeText, { color: trade.type === 'BUY' ? colors.primary : colors.danger }]}>
                      {trade.type}
                    </Text>
                  </View>
                  <Text style={styles.tradeSymbol}>{trade.symbol}</Text>
                </View>
                <Text style={styles.tradeTotal}>${trade.total.toFixed(2)}</Text>
              </View>
              <Text style={styles.tradeDetails}>
                {trade.amount.toFixed(6)} @ ${trade.price.toLocaleString()}
              </Text>
              {trade.profit !== undefined && (
                <Text style={[styles.tradeProfit, { color: trade.profit >= 0 ? colors.primary : colors.danger }]}>
                  P/L: {trade.profit >= 0 ? '+' : ''}${trade.profit.toFixed(2)}
                </Text>
              )}
              <Text style={styles.tradeReason}>{trade.reason}</Text>
            </View>
          ))
        )}
        <View style={{ height: 100 }} />
      </ScrollView>
    </SafeAreaView>
  );
}

// ============================================================
// Calculator Screen
// ============================================================
function CalculatorScreen() {
  const [startingAmount, setStartingAmount] = useState('1000');
  const [monthlyAmount, setMonthlyAmount] = useState('100');
  const [years, setYears] = useState('2');
  const [returnRate, setReturnRate] = useState('10');

  const calculateFutureValue = () => {
    const principal = parseFloat(startingAmount) || 0;
    const monthly = parseFloat(monthlyAmount) || 0;
    const yrs = parseFloat(years) || 0;
    const rate = parseFloat(returnRate) || 0;

    const monthlyRate = rate / 100 / 12;
    const months = yrs * 12;

    const fvPrincipal = principal * Math.pow(1 + monthlyRate, months);
    let fvContributions = 0;
    if (monthlyRate > 0) {
      fvContributions = monthly * ((Math.pow(1 + monthlyRate, months) - 1) / monthlyRate);
    } else {
      fvContributions = monthly * months;
    }

    return fvPrincipal + fvContributions;
  };

  const finalBalance = calculateFutureValue();
  const totalInvested = (parseFloat(startingAmount) || 0) + (parseFloat(monthlyAmount) || 0) * (parseFloat(years) || 0) * 12;
  const interestEarned = finalBalance - totalInvested;

  return (
    <SafeAreaView style={styles.container}>
      <ScrollView showsVerticalScrollIndicator={false}>
        <View style={styles.header}>
          <Text style={styles.headerTitle}>Calculator</Text>
        </View>

        {/* Result Card */}
        <View style={[styles.card, { backgroundColor: colors.primary + '10', borderColor: colors.primary + '30' }]}>
          <Text style={[styles.statLabel, { color: colors.primary }]}>Final Balance</Text>
          <Text style={[styles.priceValue, { color: colors.primary, fontSize: 36 }]}>
            ${Math.round(finalBalance).toLocaleString()}
          </Text>
          <Text style={styles.holdingLabel}>+${Math.round(interestEarned).toLocaleString()} in growth</Text>
        </View>

        {/* Inputs */}
        <View style={styles.card}>
          <View style={styles.inputGroup}>
            <Text style={styles.inputLabel}>Starting Amount ($)</Text>
            <TextInput
              style={styles.input}
              value={startingAmount}
              onChangeText={setStartingAmount}
              keyboardType="numeric"
              placeholderTextColor={colors.textMuted}
            />
          </View>

          <View style={styles.inputGroup}>
            <Text style={styles.inputLabel}>Monthly Investment ($)</Text>
            <TextInput
              style={styles.input}
              value={monthlyAmount}
              onChangeText={setMonthlyAmount}
              keyboardType="numeric"
              placeholderTextColor={colors.textMuted}
            />
          </View>

          <View style={styles.inputGroup}>
            <Text style={styles.inputLabel}>Years</Text>
            <TextInput
              style={styles.input}
              value={years}
              onChangeText={setYears}
              keyboardType="numeric"
              placeholderTextColor={colors.textMuted}
            />
          </View>

          <View style={styles.inputGroup}>
            <Text style={styles.inputLabel}>Expected Return (%)</Text>
            <TextInput
              style={styles.input}
              value={returnRate}
              onChangeText={setReturnRate}
              keyboardType="numeric"
              placeholderTextColor={colors.textMuted}
            />
          </View>
        </View>

        {/* Breakdown */}
        <View style={styles.card}>
          <Text style={styles.cardTitle}>Breakdown</Text>
          <View style={styles.holdingRow}>
            <Text style={styles.holdingLabel}>Total Invested</Text>
            <Text style={styles.holdingValue}>${totalInvested.toLocaleString()}</Text>
          </View>
          <View style={styles.holdingRow}>
            <Text style={styles.holdingLabel}>Interest Earned</Text>
            <Text style={[styles.holdingValue, { color: colors.primary }]}>
              +${Math.round(interestEarned).toLocaleString()}
            </Text>
          </View>
          <View style={styles.holdingRow}>
            <Text style={styles.holdingLabel}>ROI</Text>
            <Text style={[styles.holdingValue, { color: colors.primary }]}>
              +{totalInvested > 0 ? ((interestEarned / totalInvested) * 100).toFixed(1) : 0}%
            </Text>
          </View>
        </View>

        <View style={{ height: 100 }} />
      </ScrollView>
    </SafeAreaView>
  );
}

// ============================================================
// Settings Screen
// ============================================================
function SettingsScreen() {
  const resetPortfolio = async () => {
    Alert.alert(
      'Reset Portfolio',
      'Are you sure? This will reset your balance to $50,000 and clear all holdings.',
      [
        { text: 'Cancel', style: 'cancel' },
        {
          text: 'Reset',
          style: 'destructive',
          onPress: async () => {
            await AsyncStorage.setItem('portfolio', JSON.stringify({
              balance: 50000,
              holdings: {},
              averageCosts: {},
            }));
            await AsyncStorage.setItem('trades', JSON.stringify([]));
            Alert.alert('Success', 'Portfolio has been reset');
          },
        },
      ]
    );
  };

  return (
    <SafeAreaView style={styles.container}>
      <View style={styles.header}>
        <Text style={styles.headerTitle}>Settings</Text>
      </View>

      <View style={styles.card}>
        <Text style={styles.cardTitle}>Account</Text>
        
        <TouchableOpacity style={styles.settingItem}>
          <Text style={styles.settingText}>API Configuration</Text>
          <Text style={styles.settingArrow}>›</Text>
        </TouchableOpacity>

        <TouchableOpacity style={styles.settingItem}>
          <Text style={styles.settingText}>Notifications</Text>
          <Text style={styles.settingArrow}>›</Text>
        </TouchableOpacity>

        <TouchableOpacity style={styles.settingItem} onPress={resetPortfolio}>
          <Text style={[styles.settingText, { color: colors.danger }]}>Reset Portfolio</Text>
          <Text style={styles.settingArrow}>›</Text>
        </TouchableOpacity>
      </View>

      <View style={styles.card}>
        <Text style={styles.cardTitle}>About</Text>
        <View style={styles.aboutInfo}>
          <Text style={styles.aboutText}>TradeFlow v1.0.0</Text>
          <Text style={styles.aboutSubtext}>Built by David Alicea</Text>
          <Text style={styles.aboutSubtext}>Educational trading simulator</Text>
        </View>
      </View>
    </SafeAreaView>
  );
}

// ============================================================
// Navigation
// ============================================================
const Tab = createBottomTabNavigator();

export default function App() {
  return (
    <NavigationContainer>
      <Tab.Navigator
        screenOptions={{
          headerShown: false,
          tabBarStyle: {
            backgroundColor: colors.card,
            borderTopColor: colors.cardBorder,
            paddingBottom: 5,
            paddingTop: 5,
            height: 60,
          },
          tabBarActiveTintColor: colors.primary,
          tabBarInactiveTintColor: colors.textMuted,
        }}
      >
        <Tab.Screen
          name="Dashboard"
          component={DashboardScreen}
          options={{ tabBarIcon: () => <Text>📊</Text> }}
        />
        <Tab.Screen
          name="Trades"
          component={TradesScreen}
          options={{ tabBarIcon: () => <Text>📋</Text> }}
        />
        <Tab.Screen
          name="Calculator"
          component={CalculatorScreen}
          options={{ tabBarIcon: () => <Text>🧮</Text> }}
        />
        <Tab.Screen
          name="Settings"
          component={SettingsScreen}
          options={{ tabBarIcon: () => <Text>⚙️</Text> }}
        />
      </Tab.Navigator>
    </NavigationContainer>
  );
}

// ============================================================
// Styles
// ============================================================
const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: colors.background,
  },
  loadingContainer: {
    flex: 1,
    backgroundColor: colors.background,
    justifyContent: 'center',
    alignItems: 'center',
  },
  loadingText: {
    color: colors.text,
    fontSize: 18,
  },
  header: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    padding: 20,
  },
  headerTitle: {
    fontSize: 28,
    fontWeight: 'bold',
    color: colors.text,
  },
  statusBadge: {
    flexDirection: 'row',
    alignItems: 'center',
    paddingHorizontal: 12,
    paddingVertical: 6,
    borderRadius: 20,
  },
  statusDot: {
    width: 8,
    height: 8,
    borderRadius: 4,
    marginRight: 6,
  },
  statusText: {
    fontSize: 12,
    fontWeight: '600',
  },
  statsRow: {
    flexDirection: 'row',
    paddingHorizontal: 20,
    gap: 12,
  },
  statCard: {
    flex: 1,
    backgroundColor: colors.card,
    borderRadius: 16,
    padding: 16,
    borderWidth: 1,
    borderColor: colors.cardBorder,
  },
  statLabel: {
    color: colors.textMuted,
    fontSize: 12,
    textTransform: 'uppercase',
    letterSpacing: 1,
  },
  statValue: {
    color: colors.text,
    fontSize: 20,
    fontWeight: 'bold',
    marginTop: 4,
  },
  assetSelector: {
    flexDirection: 'row',
    paddingHorizontal: 20,
    marginTop: 20,
    gap: 8,
  },
  assetButton: {
    flex: 1,
    paddingVertical: 12,
    borderRadius: 12,
    backgroundColor: colors.card,
    borderWidth: 1,
    borderColor: colors.cardBorder,
    alignItems: 'center',
  },
  assetButtonActive: {
    backgroundColor: colors.text,
    borderColor: colors.text,
  },
  assetButtonText: {
    color: colors.textMuted,
    fontWeight: '600',
  },
  assetButtonTextActive: {
    color: colors.background,
  },
  priceCard: {
    margin: 20,
    padding: 20,
    backgroundColor: colors.card,
    borderRadius: 20,
    borderWidth: 1,
    borderColor: colors.cardBorder,
  },
  priceHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
  },
  assetName: {
    color: colors.text,
    fontSize: 18,
    fontWeight: '600',
  },
  assetSymbol: {
    color: colors.textMuted,
    fontSize: 14,
  },
  priceRight: {
    alignItems: 'flex-end',
  },
  priceValue: {
    color: colors.text,
    fontSize: 28,
    fontWeight: 'bold',
  },
  priceChange: {
    fontSize: 14,
    fontWeight: '500',
  },
  card: {
    marginHorizontal: 20,
    marginBottom: 16,
    padding: 20,
    backgroundColor: colors.card,
    borderRadius: 20,
    borderWidth: 1,
    borderColor: colors.cardBorder,
  },
  cardTitle: {
    color: colors.text,
    fontSize: 18,
    fontWeight: '600',
    marginBottom: 16,
  },
  holdingRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    marginBottom: 12,
  },
  holdingLabel: {
    color: colors.textMuted,
    fontSize: 14,
  },
  holdingValue: {
    color: colors.text,
    fontSize: 14,
    fontWeight: '600',
    fontVariant: ['tabular-nums'],
  },
  divider: {
    height: 1,
    backgroundColor: colors.cardBorder,
    marginVertical: 12,
  },
  strategyRow: {
    flexDirection: 'row',
    gap: 8,
    marginBottom: 16,
  },
  strategyButton: {
    flex: 1,
    paddingVertical: 12,
    borderRadius: 12,
    backgroundColor: colors.background,
    borderWidth: 1,
    borderColor: colors.cardBorder,
    alignItems: 'center',
  },
  strategyButtonActive: {
    backgroundColor: colors.text,
    borderColor: colors.text,
  },
  strategyButtonText: {
    color: colors.textMuted,
    fontWeight: '500',
  },
  strategyButtonTextActive: {
    color: colors.background,
  },
  inputRow: {
    flexDirection: 'row',
    gap: 12,
  },
  inputGroup: {
    flex: 1,
    marginBottom: 12,
  },
  inputLabel: {
    color: colors.textMuted,
    fontSize: 12,
    textTransform: 'uppercase',
    letterSpacing: 0.5,
    marginBottom: 8,
  },
  input: {
    backgroundColor: colors.background,
    borderWidth: 1,
    borderColor: colors.cardBorder,
    borderRadius: 12,
    padding: 14,
    color: colors.text,
    fontSize: 16,
    fontVariant: ['tabular-nums'],
  },
  toggleButton: {
    paddingVertical: 16,
    borderRadius: 14,
    alignItems: 'center',
    marginTop: 8,
  },
  toggleButtonText: {
    color: colors.text,
    fontSize: 16,
    fontWeight: '600',
  },
  tradeButtons: {
    flexDirection: 'row',
    paddingHorizontal: 20,
    gap: 12,
  },
  tradeButton: {
    flex: 1,
    paddingVertical: 16,
    borderRadius: 14,
    alignItems: 'center',
  },
  buyButton: {
    backgroundColor: colors.primary + '20',
    borderWidth: 1,
    borderColor: colors.primary + '40',
  },
  sellButton: {
    backgroundColor: colors.danger + '20',
    borderWidth: 1,
    borderColor: colors.danger + '40',
  },
  tradeButtonText: {
    fontSize: 16,
    fontWeight: '600',
    color: colors.text,
  },
  emptyState: {
    alignItems: 'center',
    paddingVertical: 60,
  },
  emptyStateIcon: {
    fontSize: 48,
    marginBottom: 12,
  },
  emptyStateText: {
    color: colors.textMuted,
    fontSize: 16,
  },
  tradeItem: {
    marginHorizontal: 20,
    marginBottom: 12,
    padding: 16,
    backgroundColor: colors.card,
    borderRadius: 16,
    borderLeftWidth: 4,
  },
  tradeHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 8,
  },
  tradeLeft: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8,
  },
  tradeBadge: {
    paddingHorizontal: 8,
    paddingVertical: 4,
    borderRadius: 6,
  },
  tradeBadgeText: {
    fontSize: 12,
    fontWeight: '600',
  },
  tradeSymbol: {
    color: colors.text,
    fontWeight: '500',
  },
  tradeTotal: {
    color: colors.text,
    fontSize: 16,
    fontWeight: '600',
  },
  tradeDetails: {
    color: colors.textMuted,
    fontSize: 13,
  },
  tradeProfit: {
    fontSize: 13,
    fontWeight: '500',
    marginTop: 4,
  },
  tradeReason: {
    color: colors.textMuted,
    fontSize: 12,
    marginTop: 4,
  },
  settingItem: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    paddingVertical: 16,
    borderBottomWidth: 1,
    borderBottomColor: colors.cardBorder,
  },
  settingText: {
    color: colors.text,
    fontSize: 16,
  },
  settingArrow: {
    color: colors.textMuted,
    fontSize: 20,
  },
  aboutInfo: {
    alignItems: 'center',
    paddingVertical: 20,
  },
  aboutText: {
    color: colors.text,
    fontSize: 16,
    fontWeight: '600',
  },
  aboutSubtext: {
    color: colors.textMuted,
    fontSize: 14,
    marginTop: 4,
  },
});
