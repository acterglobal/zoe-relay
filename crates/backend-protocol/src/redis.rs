use apalis_redis::{Config, ConnectionManager, RedisStorage};

pub struct CommandQueuer {
    storage: ConnectionManager,
}

impl CommandQueuer {
    pub fn new(redis_url: String) -> Self {
        let config = Config::new(redis_url);
        let manager = ConnectionManager::new(config).unwrap();
        Self { storage: manager }
    }

    pub fn storage<T>(&self) -> RedisStorage<T> {
        RedisStorage::new(self.storage.clone())
    }

    pub fn respond<T: Serialize + Deserialize, E: Serialize + Deserialize>(
        &self,
        id: string,
        response: Response<T, E>,
    ) -> Result<(), Error> {
        let rsp = postcard::to_vec(&response)?;
        let command = Cmd::new("LPUSH");
        command.arg(format!("zoe-backoffice-response:{id}"));
        command.arg(rsp);
        self.manager.send_packed_command(&command)?;
        Ok(())
    }
}
