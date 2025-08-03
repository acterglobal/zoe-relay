# Zoe Internal Status

## Protocol
### Relay / Wire
- ✅ Wire protocol with service definitions (Messages, Blob services) over quic
- ✅ Generic Message structures and serialization (postcard + serde)
- ✅ Cryptographic operations (ed25519, TLS certificates, mutual auth)
- ✅ Service routing by ID with start byte per quic stream
- ✅ Wire auth via ed25519 mutual certificate verification
- [ ] Upgrade additional ed25519 accounts via further auth-protocol

### Storage
- ✅ Storage RPC
- ✅ Self-encrypted storage system

### Application Models
 - [ ] not yet defined

## Relay / Backend
- ✅ CLI interface (`cargo run --bin zoe-relay -- --private-key <key>`)
- ✅ MessagesService with Redis backend integration
- ✅ Message publishing and subscription streaming
- ✅ Blob RPC Service implementation
- [ ] Storage Quotas

### ToDo:
 - [ ] Improved Message streaming:
   - [x] ignoring of emphemral messages
   - [x] store once (not once per stream)
   - [ ] separate streams per filter
 - [ ] updating of subscriptions
   - [ ] catching up on newly added subscriptions while running a subscription
 - [ ] End-2-End-Testing over redis
 - [ ] generic client interface
 - [ ] allow firehose services per allow-list
 - [ ] only accept user-set-keys for authenticated ed25519 auth if set to

## Client
- Client as per quic definition: the one connecting is the client
- ✅ Example message client with connection, subscription, and publishing
- [ ] generic client interface for relays
- [ ] Application State Machine(s)

## Bots
 - Generic bot interface that reads the firehose
 - 