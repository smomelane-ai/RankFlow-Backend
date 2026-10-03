const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());

// 🔒 CONNECT TO SUPABASE CLOUD (Safely using environment variables)
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_KEY;
const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

// 🩺 HEALTH CHECK ROUTE (Suggested by Claude to test connection status)
app.get('/health', (req, res) => res.json({ ok: true }));

// 🚏 1. DISPATCH ENDPOINT
app.post('/api/queue/dispatch', async (req, res) => {
    const { route, taxiId } = req.body;
    const dispatchFee = 2.00;

    try {
        const { data, error } = await supabase
            .from('dispatches')
            .insert([{ route, taxi_id: taxiId, fee: dispatchFee, created_at: new Date() }]);

        if (error) throw error;
        res.status(200).json({ success: true, message: 'Dispatch recorded successfully', data });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

// 💳 2. WALLET TOP-UP ENDPOINT
app.post('/api/wallet/topup', async (req, res) => {
    const { userId, amount } = req.body;

    try {
        const { data: wallet, error: fetchError } = await supabase
            .from('wallets')
            .select('balance')
            .eq('user_id', userId)
            .single();

        if (fetchError && fetchError.code !== 'PGRST116') throw fetchError;

        const currentBalance = wallet ? wallet.balance : 0;
        const newBalance = currentBalance + parseFloat(amount);

        const { data, error: saveError } = await supabase
            .from('wallets')
            .upsert({ user_id: userId, balance: newBalance, updated_at: new Date() }, { onConflict: 'user_id' });

        if (saveError) throw saveError;
        res.status(200).json({ success: true, balance: newBalance });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

// 🔑 3. PIN VERIFICATION ENDPOINT (Matches your text-based database setup)
app.post('/api/auth/verify-pin', async (req, res) => {
    const { userId, pin } = req.body;

    try {
        // Query looking up the 'id' field where your driver text 'DRV001' lives
        const { data: user, error } = await supabase
            .from('users')
            .select('id, hashed_pin')
            .eq('id', userId)
            .single();

        if (error || !user) {
            return res.status(404).json({ success: false, message: 'Wrong ID or PIN' });
        }

        if (user.hashed_pin === pin) {
            const { data: wallet } = await supabase
                .from('wallets')
                .select('balance')
                .eq('user_id', user.id)
                .single();
            
            const currentBalance = wallet ? wallet.balance : 0;
            res.status(200).json({ success: true, authenticated: true, balance: currentBalance });
        } else {
            res.status(401).json({ success: false, message: 'Wrong ID or PIN' });
        }
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

app.listen(PORT, () => {
    console.log(`Server running securely on port ${PORT}`);
});
