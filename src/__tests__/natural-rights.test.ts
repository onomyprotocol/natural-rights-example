// tslint:disable: no-var-requires no-string-literal

import { NaturalRightsClient, RemoteHttpService } from '@natural-rights/client'
import {
  NaturalRightsHttpServer,
  NaturalRightsLmdbAdapter,
  NaturalRightsLocalService
} from '@natural-rights/service'
import { Primitives } from '../DummyPrimitives'

const path = require('path')
const rimraf = require('rimraf')
const mkdirp = require('mkdirp')

describe('Natural rights integration tests', () => {
  const port = 4343
  const testDirPath = path.resolve(__dirname, './integrationtestdata')
  let adapter: NaturalRightsLmdbAdapter
  let listener: any

  async function connect(): Promise<NaturalRightsClient> {
    const deviceCryptKeyPair = await Primitives.cryptKeyGen()
    const deviceSignKeyPair = await Primitives.signKeyGen()

    return new NaturalRightsClient(
      new RemoteHttpService(Primitives, `http://localhost:${port}`),
      deviceCryptKeyPair,
      deviceSignKeyPair
    )
  }

  beforeEach(async () => {
    await new Promise((ok, fail) =>
      rimraf(testDirPath, (err: any) => {
        if (err) {
          return fail(err)
        }
        mkdirp(testDirPath, (error: any) => (error ? fail(error) : ok()))
      })
    )
    const serverKeyPair = await Primitives.signKeyGen()
    adapter = new NaturalRightsLmdbAdapter({
      path: testDirPath
    })
    const service = new NaturalRightsLocalService(Primitives, adapter)
    service.signKeyPair = serverKeyPair
    listener = new NaturalRightsHttpServer(service).listen(port, '127.0.0.1')
  })

  afterEach(async () => {
    if (listener) {
      listener.close()
    }
    if (adapter) {
      adapter.close()
    }
    await new Promise(ok => rimraf(testDirPath, ok))
  })

  describe('Proxy Re-Encryption Based Access Management', () => {
    let alice: NaturalRightsClient
    let bob: NaturalRightsClient
    let carol: NaturalRightsClient
    let eve: NaturalRightsClient

    beforeEach(async () => {
      try {
        alice = await connect()
        await alice.login()
        await alice.registerAccount()

        bob = await connect()
        await bob.login()
        await bob.registerAccount()

        carol = await connect()
        await carol.login()
        await carol.registerAccount()

        eve = await connect()
        await eve.login()
        await eve.registerAccount()
      } catch (e) {
        // tslint:disable-next-line: no-console
        console.error(e.stack || e)
        throw e
      }
    })

    it('allows alice to grant bob read access to a document', async () => {
      const {
        id: documentId,
        cryptKeyPair: docCryptKeyPair
      } = await alice.createDocument()
      await alice.grantReadAccess(documentId, 'account', bob.accountId)

      expect(await bob['_decryptDocumentEncryptionKey'](documentId)).toEqual(
        docCryptKeyPair.privKey
      )

      let eveSuccess = false
      try {
        await eve['_decryptDocumentEncryptionKey'](documentId)
        eveSuccess = true
      } catch (e) {
        expect(e).toEqual([
          {
            error: 'Unauthorized',
            payload: {
              documentId
            },
            success: false,
            type: 'DecryptDocument'
          }
        ])
      }
      expect(eveSuccess).toEqual(false)
    })

    it("allows alice to revoke bob's access to her document", async () => {
      const {
        id: documentId,
        cryptKeyPair: docCryptKeyPair
      } = await alice.createDocument()
      await alice.grantReadAccess(documentId, 'account', bob.accountId)

      expect(await bob['_decryptDocumentEncryptionKey'](documentId)).toEqual(
        docCryptKeyPair.privKey
      )
      await alice.revokeAccess(documentId, 'account', bob.accountId)

      let bobSuccess = false

      try {
        await bob['_decryptDocumentEncryptionKey'](documentId)
        bobSuccess = true
      } catch (e) {
        expect(e).toEqual([
          {
            error: 'Unauthorized',
            payload: {
              documentId
            },
            success: false,
            type: 'DecryptDocument'
          }
        ])
      }
      expect(bobSuccess).toEqual(false)
    })

    it('allows bob to grant carol read access to a document he is given read access to from alice', async () => {
      const {
        id: documentId,
        cryptKeyPair: docCryptKeyPair
      } = await alice.createDocument()
      await alice.grantReadAccess(documentId, 'account', bob.accountId)
      await bob.grantReadAccess(documentId, 'account', carol.accountId)

      expect(await carol['_decryptDocumentEncryptionKey'](documentId)).toEqual(
        docCryptKeyPair.privKey
      )

      let eveSuccess = false
      try {
        await eve['_decryptDocumentEncryptionKey'](documentId)
        eveSuccess = true
      } catch (e) {
        expect(e).toEqual([
          {
            error: 'Unauthorized',
            payload: {
              documentId
            },
            success: false,
            type: 'DecryptDocument'
          }
        ])
      }
      expect(eveSuccess).toEqual(false)
    })

    it('allows alice to grant bob access to a document through a group', async () => {
      const {
        id: documentId,
        cryptKeyPair: docCryptKeyPair
      } = await alice.createDocument()
      const groupId = await alice.createGroup()
      await alice.grantReadAccess(documentId, 'group', groupId)
      await alice.addReaderToGroup(groupId, bob.accountId)

      expect(await bob['_decryptDocumentEncryptionKey'](documentId)).toEqual(
        docCryptKeyPair.privKey
      )

      let eveSuccess = false
      try {
        await eve['_decryptDocumentEncryptionKey'](documentId)
        eveSuccess = true
      } catch (e) {
        expect(e).toEqual([
          {
            error: 'Unauthorized',
            payload: {
              documentId
            },
            success: false,
            type: 'DecryptDocument'
          }
        ])
      }
      expect(eveSuccess).toEqual(false)
    })

    it('does not allow group members to add other members', async () => {
      try {
        const { id: documentId } = await alice.createDocument()
        const groupId = await alice.createGroup()
        await alice.grantReadAccess(documentId, 'group', groupId)
        await alice.addReaderToGroup(groupId, bob.accountId)

        let bobSuccess = false
        try {
          await bob.addReaderToGroup(groupId, carol.accountId)
          bobSuccess = true
        } catch (e) {
          expect(e).toEqual([
            {
              error: 'Unauthorized',
              payload: {
                id: groupId,
                kind: 'group'
              },
              success: false,
              type: 'GetKeyPairs'
            }
          ])
        }
        expect(bobSuccess).toEqual(false)
      } catch (e) {
        // tslint:disable-next-line: no-console
        console.error(e.stack || e)
        throw e
      }
    })

    it("allows alice to revoke bob's membership in a group", async () => {
      const {
        id: documentId,
        cryptKeyPair: docCryptKeyPair
      } = await alice.createDocument()
      const groupId = await alice.createGroup()
      await alice.grantReadAccess(documentId, 'group', groupId)
      await alice.addReaderToGroup(groupId, bob.accountId)

      expect(await bob['_decryptDocumentEncryptionKey'](documentId)).toEqual(
        docCryptKeyPair.privKey
      )

      await alice.removeMemberFromGroup(groupId, bob.accountId)

      const bobSuccess = false
      try {
        await bob['_decryptDocumentEncryptionKey'](documentId)
      } catch (e) {
        expect(e).toEqual([
          {
            error: 'Unauthorized',
            payload: {
              documentId
            },
            success: false,
            type: 'DecryptDocument'
          }
        ])
      }
      expect(bobSuccess).toEqual(false)
    })

    it('allows alice to add bob as a group admin who can then add carol as a member', async () => {
      const {
        id: documentId,
        cryptKeyPair: docCryptKeyPair
      } = await alice.createDocument()
      const groupId = await alice.createGroup()
      await alice.grantReadAccess(documentId, 'group', groupId)

      await alice.addAdminToGroup(groupId, bob.accountId)
      await bob.addReaderToGroup(groupId, carol.accountId)

      expect(await carol['_decryptDocumentEncryptionKey'](documentId)).toEqual(
        docCryptKeyPair.privKey
      )
    })

    it('allows alice to revoke a groups access to a document', async () => {
      const {
        id: documentId,
        cryptKeyPair: docCryptKeyPair
      } = await alice.createDocument()
      const groupId = await alice.createGroup()
      await alice.grantReadAccess(documentId, 'group', groupId)
      await alice.addReaderToGroup(groupId, bob.accountId)

      expect(await bob['_decryptDocumentEncryptionKey'](documentId)).toEqual(
        docCryptKeyPair.privKey
      )

      await alice.revokeAccess(documentId, 'group', groupId)

      let bobSuccess = false
      try {
        await bob['_decryptDocumentEncryptionKey'](documentId)
        bobSuccess = true
      } catch (e) {
        expect(e).toEqual([
          {
            error: 'Unauthorized',
            payload: {
              documentId
            },
            success: false,
            type: 'DecryptDocument'
          }
        ])
      }
      expect(bobSuccess).toEqual(false)
    })
  })
})
