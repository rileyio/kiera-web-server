import { Server } from '.'

const server = new Server()

server.httpsServer.listen(8235, () => {
  console.log(`kiera-web listening on: 8235`)
})
