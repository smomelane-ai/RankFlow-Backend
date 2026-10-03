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

// 🚏 1. DISPATCH ENDPOINT (Saves & Updates to Supabase)
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
        // Fetch current balance
        const { data: wallet, error: fetchError } = await supabase
            .from('wallets')
            .select('balance')
            .eq('user_id', userId)
            .single();

        if (fetchError && fetchError.code !== 'PGRST116') throw fetchError; // PGRST116 means no row found

        const currentBalance = wallet ? wallet.balance : 0;
        const newBalance = currentBalance + parseFloat(amount);

        // Update or Insert new balance
        const { data, error: saveError } = await supabase
            .from('wallets')
            .upsert({ user_id: userId, balance: newBalance, updated_at: new Date() }, { onConflict: 'user_id' });

        if (saveError) throw saveError;
        res.status(200).json({ success: true, balance: newBalance });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

// 🔑 3. PIN VERIFICATION ENDPOINT
app.post('/api/auth/verify-pin', async (req, res) => {
    const { userId, pin } = req.body;

    try {
        const { data: user, error } = await supabase
            .from('users')
            .select('hashed_pin')
            .eq('id', userId)
            .single();

        if (error || !user) {
            return res.status(404).json({ success: false, message: 'User or PIN record not found' });
        }

        // Simple validation comparison (Adjust if your database uses deep encryption hashes)
        if (user.hashed_pin === pin) {
            res.status(200).json({ success: true, authenticated: true });
        } else {
            res.status(401).json({ success: false, message: 'Invalid PIN configuration' });
        }
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

app.listen(PORT, () => {
    console.log(`Server running securely on port ${PORT}`);
});
