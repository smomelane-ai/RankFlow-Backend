const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());

// 🔐 CONNECT TO SUPABASE CLOUD (Paste your keys inside the single quotes below)
const SUPABASE_URL = 'https://qmfjsdvsgvoixyhgqflg.supabase.co';
const SUPABASE_KEY = 'sb_publishable_DAWxXfh5fWbiQeEIExcCFw_78EN0oi5';
const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

// ----------------------------------------------------
// 🚦 DISPATCH ENDPOINT (Saves & Updates to Supabase)
// ----------------------------------------------------
app.post('/api/queue/dispatch', async (req, res) => {
    const { route, taxiId } = req.body; 
    const dispatchFee = 2.00;

    const { data: taxi, error: fetchErr } = await supabase
        .from('taxis')
        .select('*')
        .eq('id', taxiId)
        .single();

    if (fetchErr || !taxi) {
        return res.status(404).json({ error: "Vehicle registration registry entity not found." });
    }

    if (taxi.wallet_balance < dispatchFee) {
        return res.status(402).json({ error: `Insufficient funds. Balance: R${taxi.wallet_balance.toFixed(2)}.` });
    }

    const newBalance = taxi.wallet_balance - dispatchFee;

    const { error: updateErr } = await supabase
        .from('taxis')
        .update({ wallet_balance: newBalance, status: 'Dispatched' })
        .eq('id', taxiId);

    if (updateErr) {
        return res.status(500).json({ error: "Database transaction update failed." });
    }

    await supabase.from('logs').insert([{ event: `${taxi.plate} dispatched. R${dispatchFee} deducted.` }]);

    res.json({ status: "Dispatched", taxiId: taxi.id, balance: newBalance });
});

// ----------------------------------------------------
// 💳 SECURE TOP-UP ENDPOINT (Validates via Supabase)
// ----------------------------------------------------
app.post('/api/wallet/topup', async (req, res) => {
    const { token } = req.body; 
    const taxiId = 1; 

    const { data: voucher, error: vErr } = await supabase
        .from('vouchers')
        .select('*')
        .eq('code', token)
        .eq('used', false)
        .single();

    if (vErr || !voucher) {
        return res.status(400).json({ error: "The entered voucher PIN is invalid or already spent." });
    }

    const { data: taxi } = await supabase.from('taxis').select('*').eq('id', taxiId).single();
    const updatedBalance = taxi.wallet_balance + voucher.value;

    await supabase.from('taxis').update({ wallet_balance: updatedBalance }).eq('id', taxiId);
    await supabase.from('vouchers').update({ used: true }).eq('id', voucher.id); 
    await supabase.from('logs').insert([{ event: `ID ${taxiId} loaded voucher token value R${voucher.value}` }]);

    res.json({ 
        balance: updatedBalance, 
        added: voucher.value 
    });
});

app.listen(PORT, () => console.log(`🚕 Persistent Cloud Engine active at http://localhost:${PORT}`));
