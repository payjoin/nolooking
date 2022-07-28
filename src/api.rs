use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use bitcoin::{Address, Script, TxOut};

use crate::ScheduledPayJoin;

#[derive(Default)]
pub(crate) struct PayJoinScheduler {
    // maps scheduled pjs via spk
    by_spk: HashMap<Script, ScheduledPayJoin>,
}

impl PayJoinScheduler {
    fn insert(&mut self, addr: &Address, pj: &ScheduledPayJoin) -> Result<(), ()> {
        let current_pj = &*self.by_spk.entry(addr.script_pubkey()).or_insert(pj.clone());
        if current_pj == pj {
            Err(()) // not inserted
        } else {
            Ok(()) // inserted
        }
    }

    /// pop scheduled payjoin alongside txout
    fn find_mut<'a, I>(&mut self, mut txouts: I) -> Option<(&'a mut TxOut, ScheduledPayJoin)>
    where
        I: Iterator<Item = &'a mut TxOut>,
    {
        txouts.find_map(|txo| self.by_spk.remove(&txo.script_pubkey).map(|pj| (txo, pj)))
    }
}

pub(crate) struct Handler {
    lnd_client: tonic_lnd::Client, // TODO: make this generic
    scheduler: Arc<Mutex<PayJoinScheduler>>,
}

pub(crate) mod util {
    use std::collections::HashMap;

    use hyper::Request;

    pub(crate) fn get_query_map(req: &hyper::Request<hyper::Body>) -> HashMap<&str, &str> {
        req.uri()
            .query()
            .into_iter()
            .flat_map(|query| query.split('&'))
            .map(|kv| {
                let eq_pos = kv.find('=').unwrap();
                (&kv[..eq_pos], &kv[(eq_pos + 1)..])
            })
            .collect::<std::collections::HashMap<_, _>>()
    }
}
