# Groups

Groups are a shared encrypted "space" where multiple users exchange messages

## Group Architecture

### Group Components
- **Shared Tag**: A unique identifier derived from the hash of the initial group creation message
- **Shared AES Key**: Used to encrypt and decrypt group content
- **PQXDH Inboxes**: User-published inboxes that enable direct client-to-client connections