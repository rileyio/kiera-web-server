import { Server } from '.'

const server = new Server()

server.server.listen(8235, () => {
  console.log(`kiera-web listening on: 8235`, server.isHTTPSSet ? 'https' : 'http')
})
