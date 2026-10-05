const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const { createClient } = require('@supabase/supabase-js');

const app = express();
app.set('trust proxy', 1); // so we see each visitor's real address behind Render
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());

// Connect to Supabase (the service_role key lives only in Render's Environment page)
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);

const DISPATCH_FEE = 2.0;
const MAX_TRIES = 5; // wrong PINs or codes allowed per person in 15 minutes
const LOCK_MS = 15 * 60 * 1000;
const OFFER_SECONDS = 30; // how long a driver has to accept a dispatch
const TOKEN_HOURS = 12; // how long a login lasts
const ROUTES = ['Durban to Inanda', 'Durban to KwaMashu', 'Umlazi to CBD', 'Pinetown to KwaMashu'];
const ACTIVE = ['In Queue', 'Offered', 'Break'];

/* ---------- Login tokens (signed with TOKEN_SECRET, no extra libraries) ---------- */
const SECRET = process.env.TOKEN_SECRET || crypto.randomBytes(32).toString('hex');
if (!process.env.TOKEN_SECRET) console.warn('TOKEN_SECRET is not set: everyone is logged out whenever the server restarts.');

const sign = (p) => crypto.createHmac('sha256', SECRET).update(p).digest('base64url');
function makeToken(user) {
    const p = Buffer.from(JSON.stringify({ id: user.id, role: user.role, exp: Date.now() + TOKEN_HOURS * 3600 * 1000 })).toString('base64url');
    return p + '.' + sign(p);
}
function readToken(t) {
    try {
        const [p, s] = String(t).split('.');
        const a = Buffer.from(s || ''), b = Buffer.from(sign(p));
        if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
        const d = JSON.parse(Buffer.from(p, 'base64url').toString());
        return d.exp > Date.now() ? d : null;
    } catch (e) { return null; }
}
// Use auth() for any logged-in user, or auth('manager') / auth('driver') for one role
function auth(...roles) {
    return (req, res, next) => {
        const u = readToken((req.headers.authorization || '').replace('Bearer ', ''));
        if (!u) return res.status(401).json({ success: false, error: 'Please log in again' });
        if (roles.length && !roles.includes(u.role)) return res.status(403).json({ success: false, error: 'Not allowed for your role' });
        req.user = u;
        next();
    };
}

/* ---------- PIN hashing (built in, no extra libraries) ---------- */
const scrypt = (pw, salt) => new Promise((ok, no) => crypto.scrypt(pw, salt, 32, (e, k) => (e ? no(e) : ok(k))));
async function hashPin(pin) {
    const salt = crypto.randomBytes(16);
    return 'scrypt$' + salt.toString('hex') + '$' + (await scrypt(String(pin), salt)).toString('hex');
}
async function checkPin(pin, stored) {
    stored = String(stored);
    if (stored.startsWith('scrypt$')) {
        const [, salt, hash] = stored.split('$');
        const k = await scrypt(String(pin), Buffer.from(salt, 'hex'));
        const h = Buffer.from(hash, 'hex');
        return k.length === h.length && crypto.timingSafeEqual(k, h);
    }
    return stored === String(pin); // an old plain PIN: it is turned into a hash after a successful login
}

/* ---------- Lock out repeated wrong guesses (kept in memory) ---------- */
const fails = new Map();
const locked = (key, max = MAX_TRIES) => { const f = fails.get(key); return !!f && Date.now() - f.first < LOCK_MS && f.n >= max; };
function addFail(key) {
    const f = fails.get(key);
    if (!f || Date.now() - f.first >= LOCK_MS) fails.set(key, { n: 1, first: Date.now() }); else f.n++;
}
setInterval(() => { for (const [k, f] of fails) if (Date.now() - f.first >= LOCK_MS) fails.delete(k); }, 10 * 60 * 1000);

/* ---------- Helpers ---------- */
function fail(res, err, status = 500) {
    console.error(err);
    res.status(status).json({ success: false, error: 'Something went wrong on the server' });
}
const cleanPlate = (p) => String(p || '').trim().toUpperCase().slice(0, 20);

// Take a fee from a wallet. Only succeeds if the balance did not change in between.
async function chargeWallet(userId, amount) {
    const { data: w } = await supabase.from('wallets').select('balance').eq('user_id', userId).maybeSingle();
    if (!w) return { error: 'Wallet not found', status: 404 };
    const current = Number(w.balance);
    if (current < amount) return { error: 'Not enough balance. Top up first.', status: 402, balance: current };
    const next = +(current - amount).toFixed(2);
    const { data: up, error } = await supabase.from('wallets')
        .update({ balance: next, updated_at: new Date() }).eq('user_id', userId).eq('balance', w.balance).select();
    if (error) throw error;
    if (!up || up.length === 0) return { error: 'Balance changed. Please try again.', status: 409 };
    return { balance: next, previous: current };
}

// Add money to a wallet. Only succeeds if the balance did not change in between.
async function creditWallet(userId, amount) {
    for (let i = 0; i < 3; i++) {
        const { data: w } = await supabase.from('wallets').select('balance').eq('user_id', userId).maybeSingle();
        if (!w) return { error: 'Wallet not found', status: 404 };
        const next = +(Number(w.balance) + amount).toFixed(2);
        const { data: up, error } = await supabase.from('wallets')
            .update({ balance: next, updated_at: new Date() }).eq('user_id', userId).eq('balance', w.balance).select();
        if (error) throw error;
        if (up && up.length) return { balance: next };
    }
    return { error: 'Balance changed. Please try again.', status: 409 };
}

// Offers nobody answered within 30 seconds go to the back of the queue
async function expireOffers(route) {
    const cutoff = new Date(Date.now() - OFFER_SECONDS * 1000).toISOString();
    await supabase.from('queue_entries')
        .update({ status: 'In Queue', joined_at: new Date().toISOString(), offered_at: null })
        .eq('route', route).eq('status', 'Offered').lt('offered_at', cutoff);
}

/* ---------- Basic ---------- */
app.get('/health', (req, res) => res.json({ ok: true }));

/* ---------- Login ---------- */
app.post('/api/auth/verify-pin', async (req, res) => {
    const userId = String(req.body.userId || '').trim().toUpperCase().slice(0, 30);
    const pin = String(req.body.pin || '');
    if (!userId || !pin) return res.status(400).json({ success: false, message: 'ID and PIN are required' });

    const keyPerson = 'login|' + req.ip + '|' + userId, keyId = 'login|' + userId;
    if (locked(keyPerson) || locked(keyId, 20)) {
        return res.status(429).json({ success: false, message: 'Too many wrong tries. Please wait 15 minutes.' });
    }
    try {
        const { data: user, error } = await supabase.from('users')
            .select('id, hashed_pin, role, full_name, plate').eq('id', userId).maybeSingle();
        if (error) throw error;
        const valid = user && /^\d{4}$/.test(pin) && (await checkPin(pin, user.hashed_pin));
        if (!valid) {
            addFail(keyPerson); addFail(keyId);
            return res.status(401).json({ success: false, message: 'Wrong ID or PIN' });
        }
        fails.delete(keyPerson);
        if (!String(user.hashed_pin).startsWith('scrypt$')) { // upgrade an old plain PIN to a hash
            await supabase.from('users').update({ hashed_pin: await hashPin(pin) }).eq('id', user.id);
        }
        const { data: wallet } = await supabase.from('wallets').select('balance').eq('user_id', user.id).maybeSingle();
        res.json({
            success: true, authenticated: true,
            balance: wallet ? Number(wallet.balance) : 0,
            token: makeToken(user),
            user: { id: user.id, role: user.role, name: user.full_name, plate: user.plate }
        });
    } catch (err) { fail(res, err); }
});

/* ---------- Wallet: top up only with a one-time code ---------- */
app.post('/api/wallet/redeem', auth('driver'), async (req, res) => {
    const code = String(req.body.code || '').toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 12);
    const key = 'redeem|' + req.user.id;
    if (locked(key)) return res.status(429).json({ success: false, error: 'Too many wrong codes. Please wait 15 minutes.' });
    try {
        const { data: t, error } = await supabase.from('topup_tokens')
            .update({ used_by: req.user.id, used_at: new Date().toISOString() })
            .eq('code', code).is('used_at', null).select().maybeSingle();
        if (error) throw error;
        if (!t) { addFail(key); return res.status(400).json({ success: false, error: 'That code is not valid or was already used' }); }
        const c = await creditWallet(req.user.id, Number(t.amount));
        if (c.error) {
            await supabase.from('topup_tokens').update({ used_by: null, used_at: null }).eq('code', code); // give the code back
            return res.status(c.status).json({ success: false, error: c.error });
        }
        fails.delete(key);
        res.json({ success: true, added: Number(t.amount), balance: c.balance });
    } catch (err) { fail(res, err); }
});

/* ---------- Live queue ---------- */

// Everyone logged in can see the queue for a route
app.get('/api/queue', auth(), async (req, res) => {
    const route = req.query.route;
    if (!ROUTES.includes(route)) return res.status(400).json({ success: false, error: 'Unknown route' });
    try {
        await expireOffers(route);
        const { data: queue, error } = await supabase.from('queue_entries').select('*')
            .eq('route', route).in('status', ACTIVE).order('joined_at', { ascending: true });
        if (error) throw error;
        const { data: recent } = await supabase.from('queue_entries').select('*')
            .eq('route', route).eq('status', 'Dispatched').order('joined_at', { ascending: false }).limit(5);
        const now = Date.now();
        res.json({
            success: true,
            queue: queue.map((e) => e.status === 'Offered'
                ? { ...e, secondsLeft: Math.max(0, OFFER_SECONDS - Math.floor((now - new Date(e.offered_at)) / 1000)) } : e),
            recent: recent || []
        });
    } catch (err) { fail(res, err); }
});

// A driver checks into the queue with their own plate. A manager can add any taxi by plate.
app.post('/api/queue/join', auth(), async (req, res) => {
    const { route } = req.body;
    if (!ROUTES.includes(route)) return res.status(400).json({ success: false, error: 'Unknown route' });
    try {
        let plate, driverId = null, driverName = null;
        if (req.user.role === 'driver') {
            const { data: me } = await supabase.from('users').select('id, full_name, plate').eq('id', req.user.id).maybeSingle();
            if (!me || !me.plate) return res.status(400).json({ success: false, error: 'Your account has no number plate yet' });
            plate = cleanPlate(me.plate); driverId = me.id; driverName = me.full_name;
        } else {
            plate = cleanPlate(req.body.plate);
            driverName = String(req.body.driverName || '').trim().slice(0, 60) || 'Driver TBC';
            if (plate.length < 4) return res.status(400).json({ success: false, error: 'Enter the number plate' });
        }
        const { data: dup } = await supabase.from('queue_entries').select('id').eq('plate', plate).in('status', ACTIVE).limit(1);
        if (dup && dup.length) return res.status(409).json({ success: false, error: 'This taxi is already in a queue' });
        const { data, error } = await supabase.from('queue_entries')
            .insert([{ route, plate, driver_id: driverId, driver_name: driverName, status: 'In Queue' }]).select().single();
        if (error) throw error;
        res.json({ success: true, entry: data });
    } catch (err) { fail(res, err); }
});

// A driver leaves the queue
app.post('/api/queue/leave', auth('driver'), async (req, res) => {
    try {
        const { error } = await supabase.from('queue_entries').delete().eq('driver_id', req.user.id).in('status', ['In Queue', 'Break']);
        if (error) throw error;
        res.json({ success: true });
    } catch (err) { fail(res, err); }
});

// Manager: offer the trip to the first taxi in line
app.post('/api/queue/dispatch-next', auth('manager'), async (req, res) => {
    const { route } = req.body;
    if (!ROUTES.includes(route)) return res.status(400).json({ success: false, error: 'Unknown route' });
    try {
        await expireOffers(route);
        const { data: waiting } = await supabase.from('queue_entries').select('id').eq('route', route).eq('status', 'Offered').limit(1);
        if (waiting && waiting.length) return res.status(409).json({ success: false, error: 'Waiting for a driver to answer the last dispatch' });
        const { data: head } = await supabase.from('queue_entries').select('*').eq('route', route).eq('status', 'In Queue')
            .order('joined_at', { ascending: true }).limit(1).maybeSingle();
        if (!head) return res.status(404).json({ success: false, error: 'No taxis waiting on this route' });

        if (head.driver_id) {
            // A registered driver gets 30 seconds to accept on their phone
            await supabase.from('queue_entries').update({ status: 'Offered', offered_at: new Date().toISOString() }).eq('id', head.id);
            return res.json({ success: true, status: 'Offered', entry: head });
        }
        // A taxi added by hand has no phone, so it is dispatched straight away (no fee)
        await supabase.from('queue_entries').update({ status: 'Dispatched' }).eq('id', head.id);
        await supabase.from('dispatches').insert([{ route, taxi_id: head.plate, fee: 0, created_at: new Date() }]);
        res.json({ success: true, status: 'Dispatched', entry: head });
    } catch (err) { fail(res, err); }
});

// Driver accepts the offer: the fee is taken and the dispatch is recorded
app.post('/api/queue/accept', auth('driver'), async (req, res) => {
    try {
        const { data: e } = await supabase.from('queue_entries').select('*').eq('driver_id', req.user.id).eq('status', 'Offered').maybeSingle();
        if (!e) return res.status(404).json({ success: false, error: 'No dispatch is waiting for you' });
        if (Date.now() - new Date(e.offered_at) > OFFER_SECONDS * 1000) {
            await expireOffers(e.route);
            return res.status(410).json({ success: false, error: 'The offer ran out of time' });
        }
        const c = await chargeWallet(req.user.id, DISPATCH_FEE);
        if (c.error) return res.status(c.status).json({ success: false, error: c.error, balance: c.balance });
        const { error } = await supabase.from('dispatches').insert([{ route: e.route, taxi_id: e.plate, driver_id: req.user.id, fee: DISPATCH_FEE, created_at: new Date() }]);
        if (error) {
            await supabase.from('wallets').update({ balance: c.previous }).eq('user_id', req.user.id);
            throw error;
        }
        await supabase.from('queue_entries').update({ status: 'Dispatched' }).eq('id', e.id);
        res.json({ success: true, balance: c.balance });
    } catch (err) { fail(res, err); }
});

// Driver rejects: goes to the back of the queue
app.post('/api/queue/reject', auth('driver'), async (req, res) => {
    try {
        const { error } = await supabase.from('queue_entries')
            .update({ status: 'In Queue', joined_at: new Date().toISOString(), offered_at: null })
            .eq('driver_id', req.user.id).eq('status', 'Offered');
        if (error) throw error;
        res.json({ success: true });
    } catch (err) { fail(res, err); }
});

// Manager: put a taxi on break, or bring it back
app.post('/api/queue/break', auth('manager'), async (req, res) => {
    try {
        const { data: e } = await supabase.from('queue_entries').select('id, status').eq('id', req.body.id).maybeSingle();
        if (!e || !['In Queue', 'Break'].includes(e.status)) return res.status(404).json({ success: false, error: 'Taxi not found' });
        await supabase.from('queue_entries').update({ status: e.status === 'Break' ? 'In Queue' : 'Break' }).eq('id', e.id);
        res.json({ success: true });
    } catch (err) { fail(res, err); }
});

// Manager removes a taxi from the queue
app.post('/api/queue/remove', auth('manager'), async (req, res) => {
    try {
        await supabase.from('queue_entries').delete().eq('id', req.body.id).in('status', ACTIVE);
        res.json({ success: true });
    } catch (err) { fail(res, err); }
});

// A dispatched taxi comes back to the end of the queue (manager, or the driver for their own taxi)
app.post('/api/queue/rejoin', auth(), async (req, res) => {
    try {
        const { data: e } = await supabase.from('queue_entries').select('*').eq('id', req.body.id).eq('status', 'Dispatched').maybeSingle();
        if (!e) return res.status(404).json({ success: false, error: 'Taxi not found' });
        if (req.user.role === 'driver' && e.driver_id !== req.user.id) return res.status(403).json({ success: false, error: 'Not your taxi' });
        await supabase.from('queue_entries').update({ status: 'In Queue', joined_at: new Date().toISOString(), offered_at: null }).eq('id', e.id);
        res.json({ success: true });
    } catch (err) { fail(res, err); }
});

/* ---------- Admin (you only) ---------- */
const adminOnly = auth('admin');
const randomPin = () => String(crypto.randomInt(0, 10000)).padStart(4, '0');
const bad = (res, msg) => res.status(400).json({ success: false, error: msg });

// Everyone on the system, with wallet balances
app.get('/api/admin/users', adminOnly, async (req, res) => {
    try {
        const { data: users, error } = await supabase.from('users')
            .select('id, role, full_name, plate, owner_id, created_at').order('created_at', { ascending: true });
        if (error) throw error;
        const { data: w } = await supabase.from('wallets').select('user_id, balance');
        const bal = Object.fromEntries((w || []).map((x) => [x.user_id, Number(x.balance)]));
        res.json({ success: true, users: users.map((u) => ({ ...u, balance: bal[u.id] ?? null })) });
    } catch (err) { fail(res, err); }
});

// Create a driver, owner or rank manager. The PIN is shown to you once.
app.post('/api/admin/users', adminOnly, async (req, res) => {
    const id = String(req.body.id || '').trim().toUpperCase();
    const role = req.body.role, name = String(req.body.name || '').trim().slice(0, 60);
    const plate = cleanPlate(req.body.plate);
    const ownerId = String(req.body.ownerId || '').trim().toUpperCase() || null;
    let pin = String(req.body.pin || '');
    if (!/^[A-Z0-9]{3,12}$/.test(id)) return bad(res, 'The ID must be 3 to 12 letters or numbers');
    if (!['driver', 'owner', 'manager'].includes(role)) return bad(res, 'Choose driver, owner or manager');
    if (!name) return bad(res, 'Enter a name');
    if (role === 'driver' && plate.length < 4) return bad(res, 'Drivers need a number plate');
    if (pin && !/^\d{4}$/.test(pin)) return bad(res, 'A PIN must be 4 digits');
    if (!pin) pin = randomPin();
    try {
        const { data: exists } = await supabase.from('users').select('id').eq('id', id).maybeSingle();
        if (exists) return res.status(409).json({ success: false, error: 'That ID is already used' });
        if (ownerId) {
            const { data: o } = await supabase.from('users').select('id').eq('id', ownerId).eq('role', 'owner').maybeSingle();
            if (!o) return bad(res, 'Owner ID not found');
        }
        const { error } = await supabase.from('users').insert([{
            id, hashed_pin: await hashPin(pin), role, full_name: name,
            plate: role === 'driver' ? plate : null, owner_id: role === 'driver' ? ownerId : null
        }]);
        if (error) throw error;
        if (role === 'driver') {
            const { error: we } = await supabase.from('wallets').insert([{ user_id: id, balance: 0 }]);
            if (we) { await supabase.from('users').delete().eq('id', id); throw we; }
        }
        res.json({ success: true, id, role, name, pin });
    } catch (err) { fail(res, err); }
});

// Give someone a new PIN (shown to you once)
app.post('/api/admin/reset-pin', adminOnly, async (req, res) => {
    const id = String(req.body.id || '').trim().toUpperCase();
    try {
        const pin = randomPin();
        const { data, error } = await supabase.from('users').update({ hashed_pin: await hashPin(pin) }).eq('id', id).select('id');
        if (error) throw error;
        if (!data || !data.length) return res.status(404).json({ success: false, error: 'ID not found' });
        fails.delete('login|' + id);
        res.json({ success: true, id, pin });
    } catch (err) { fail(res, err); }
});

// Make a batch of one-time top-up codes for a seller
app.post('/api/admin/codes', adminOnly, async (req, res) => {
    const amount = Number(req.body.amount), qty = Math.floor(Number(req.body.count));
    const seller = String(req.body.seller || '').trim().slice(0, 60);
    const reference = String(req.body.reference || '').trim().slice(0, 60) || null;
    if (!(amount >= 5 && amount <= 1000)) return bad(res, 'Amount must be between R5 and R1,000');
    if (!(qty >= 1 && qty <= 50)) return bad(res, 'Make between 1 and 50 codes at a time');
    if (!seller) return bad(res, 'Enter the seller\'s name');
    try {
        const { data: batch, error } = await supabase.from('topup_batches').insert([{ seller, reference, amount, quantity: qty }]).select().single();
        if (error) throw error;
        const codes = Array.from({ length: qty }, () => crypto.randomBytes(6).toString('hex').toUpperCase());
        const { error: te } = await supabase.from('topup_tokens').insert(codes.map((code) => ({ code, amount, batch_id: batch.id })));
        if (te) { await supabase.from('topup_batches').delete().eq('id', batch.id); throw te; }
        res.json({ success: true, batch, codes });
    } catch (err) { fail(res, err); }
});

// The last batches, with which codes are used
app.get('/api/admin/batches', adminOnly, async (req, res) => {
    try {
        const { data: batches, error } = await supabase.from('topup_batches').select('*').order('created_at', { ascending: false }).limit(15);
        if (error) throw error;
        const ids = batches.map((b) => b.id);
        const { data: tokens } = ids.length ? await supabase.from('topup_tokens').select('code, amount, batch_id, used_by, used_at').in('batch_id', ids) : { data: [] };
        res.json({ success: true, batches: batches.map((b) => ({ ...b, codes: (tokens || []).filter((t) => t.batch_id === b.id) })) });
    } catch (err) { fail(res, err); }
});

// Credit a wallet after you have seen the money in your bank account
app.post('/api/admin/payments', adminOnly, async (req, res) => {
    const userId = String(req.body.userId || '').trim().toUpperCase();
    const amount = Number(req.body.amount);
    const method = req.body.method;
    const reference = String(req.body.reference || '').trim().slice(0, 40) || null;
    if (!['PayShap', 'EFT', 'eWallet', 'Cash'].includes(method)) return bad(res, 'Choose how they paid');
    if (!(amount >= 1 && amount <= 5000)) return bad(res, 'Amount must be between R1 and R5,000');
    if (method !== 'Cash' && (!reference || reference.length < 3)) return bad(res, 'Enter the bank reference so the same payment cannot be added twice');
    try {
        const { data: u } = await supabase.from('users').select('id').eq('id', userId).eq('role', 'driver').maybeSingle();
        if (!u) return bad(res, 'Driver ID not found');
        const { data: pay, error } = await supabase.from('wallet_payments').insert([{ user_id: userId, amount, method, reference }]).select().single();
        if (error) {
            if (error.code === '23505') return res.status(409).json({ success: false, error: 'That reference was already used' });
            throw error;
        }
        const c = await creditWallet(userId, amount);
        if (c.error) { await supabase.from('wallet_payments').delete().eq('id', pay.id); return res.status(c.status).json({ success: false, error: c.error }); }
        res.json({ success: true, balance: c.balance });
    } catch (err) { fail(res, err); }
});

app.get('/api/admin/payments', adminOnly, async (req, res) => {
    try {
        const { data, error } = await supabase.from('wallet_payments').select('*').order('created_at', { ascending: false }).limit(25);
        if (error) throw error;
        res.json({ success: true, payments: data });
    } catch (err) { fail(res, err); }
});

/* ---------- Owner dashboard: trips each driver accepted ---------- */
const SAST_MS = 2 * 3600 * 1000; // South Africa is UTC+2 all year
const dayKey = (d) => new Date(new Date(d).getTime() + SAST_MS).toISOString().slice(0, 10);

app.get('/api/owner/summary', auth('owner'), async (req, res) => {
    const date = /^\d{4}-\d{2}-\d{2}$/.test(req.query.date || '') ? req.query.date : dayKey(Date.now());
    const start = new Date(date + 'T00:00:00+02:00');
    if (isNaN(start)) return bad(res, 'Bad date');
    const end = new Date(start.getTime() + 86400000), from7 = new Date(start.getTime() - 6 * 86400000);
    try {
        const { data: drivers, error } = await supabase.from('users').select('id, full_name, plate')
            .eq('owner_id', req.user.id).eq('role', 'driver').order('full_name');
        if (error) throw error;
        let rows = [];
        if (drivers.length) {
            const { data, error: de } = await supabase.from('dispatches').select('driver_id, route, fee, created_at')
                .in('driver_id', drivers.map((d) => d.id)).gte('created_at', from7.toISOString()).lt('created_at', end.toISOString())
                .order('created_at', { ascending: true });
            if (de) throw de;
            rows = data || [];
        }
        const out = drivers.map((d) => {
            const mine = rows.filter((r) => r.driver_id === d.id), today = mine.filter((r) => new Date(r.created_at) >= start), week = {};
            mine.forEach((r) => { const k = dayKey(r.created_at); week[k] = (week[k] || 0) + 1; });
            return { id: d.id, name: d.full_name, plate: d.plate, trips: today.length,
                fees: today.reduce((s, r) => s + Number(r.fee), 0),
                list: today.map((r) => ({ time: r.created_at, route: r.route })), week };
        });
        res.json({ success: true, date, drivers: out, total: out.reduce((s, d) => s + d.trips, 0) });
    } catch (err) { fail(res, err); }
});

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
