const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());

// Connect to Supabase (use the service_role key in SUPABASE_KEY on the server only)
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);

const DISPATCH_FEE = 2.0;
const MAX_TOPUP = 500; // DEMO safety cap per request. Remove once top-ups are tied to real payments.

// Log the real error for you in Render Logs, but send the app a plain message
function fail(res, err, status = 500) {
    console.error(err);
    res.status(status).json({ success: false, error: 'Something went wrong on the server' });
}

// Health check
app.get('/health', (req, res) => res.json({ ok: true }));

// 1. DISPATCH: checks balance, takes the R2.00 fee, records the dispatch, returns the new balance
app.post('/api/queue/dispatch', async (req, res) => {
    const { route, taxiId, userId } = req.body;
    if (!route || !taxiId || !userId) {
        return res.status(400).json({ success: false, error: 'Route, fleet ID and user are required' });
    }

    try {
        const { data: wallet, error: walletError } = await supabase
            .from('wallets').select('balance').eq('user_id', userId).single();
        if (walletError || !wallet) {
            return res.status(404).json({ success: false, error: 'Wallet not found' });
        }

        const current = Number(wallet.balance);
        if (current < DISPATCH_FEE) {
            return res.status(402).json({ success: false, error: 'Not enough balance. Top up first.', balance: current });
        }
        const newBalance = +(current - DISPATCH_FEE).toFixed(2);

        // Only deduct if the balance has not changed since we read it (stops double-spend races)
        const { data: updated, error: deductError } = await supabase
            .from('wallets').update({ balance: newBalance, updated_at: new Date() })
            .eq('user_id', userId).eq('balance', wallet.balance).select();
        if (deductError) throw deductError;
        if (!updated || updated.length === 0) {
            return res.status(409).json({ success: false, error: 'Balance changed. Please try again.' });
        }

        const { error: insertError } = await supabase
            .from('dispatches').insert([{ route, taxi_id: taxiId, fee: DISPATCH_FEE, created_at: new Date() }]);
        if (insertError) {
            // Dispatch failed to save, so give the fee back
            await supabase.from('wallets').update({ balance: current }).eq('user_id', userId);
            throw insertError;
        }

        res.status(200).json({ success: true, message: 'Dispatch recorded successfully', balance: newBalance });
    } catch (err) { fail(res, err); }
});

// 2. WALLET TOP-UP (DEMO ONLY: anyone can add funds. Needs a payment or token check before real use.)
app.post('/api/wallet/topup', async (req, res) => {
    const { userId, amount } = req.body;
    const value = Number(amount);
    if (!userId || !(value > 0) || value > MAX_TOPUP) {
        return res.status(400).json({ success: false, error: `Amount must be between R1 and R${MAX_TOPUP}` });
    }

    try {
        const { data: wallet, error: fetchError } = await supabase
            .from('wallets').select('balance').eq('user_id', userId).single();
        if (fetchError && fetchError.code !== 'PGRST116') throw fetchError;

        const newBalance = +((wallet ? Number(wallet.balance) : 0) + value).toFixed(2);
        const { error: saveError } = await supabase
            .from('wallets').upsert({ user_id: userId, balance: newBalance, updated_at: new Date() }, { onConflict: 'user_id' });
        if (saveError) throw saveError;

        res.status(200).json({ success: true, balance: newBalance });
    } catch (err) { fail(res, err); }
});

// 3. PIN VERIFICATION (works with a plain PIN now, and with a bcrypt hash later)
app.post('/api/auth/verify-pin', async (req, res) => {
    const { userId, pin } = req.body;
    if (!userId || !pin) {
        return res.status(400).json({ success: false, message: 'Driver ID and PIN are required' });
    }

    try {
        const { data: user, error } = await supabase
            .from('users').select('id, hashed_pin').eq('id', userId).single();
                console.log('Login attempt for:', JSON.stringify(userId));
        if (error) console.error('Lookup error:', error.code, error.message);
        if (error || !user) {
            return res.status(404).json({ success: false, message: 'Wrong ID or PIN' });
        }

        let valid;
        if (String(user.hashed_pin).startsWith('$2')) {
            valid = await require('bcryptjs').compare(String(pin), user.hashed_pin); // npm i bcryptjs
        } else {
            valid = user.hashed_pin === String(pin);
        }
        if (!valid) return res.status(401).json({ success: false, message: 'Wrong ID or PIN' });

        const { data: wallet } = await supabase
            .from('wallets').select('balance').eq('user_id', user.id).single();
        res.status(200).json({ success: true, authenticated: true, balance: wallet ? Number(wallet.balance) : 0 });
    } catch (err) { fail(res, err); }
});

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
