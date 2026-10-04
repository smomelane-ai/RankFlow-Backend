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
        const { error } = await supabase.from('dispatches').insert([{ route: e.route, taxi_id: e.plate, fee: DISPATCH_FEE, created_at: new Date() }]);
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

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
