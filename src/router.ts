import { Server } from '.'
import { Route } from './objects/route'

export class Router {
  private server: Server
  private routes: Array<Route>

  constructor(server: Server, routes: Array<Route>) {
    this.server = server
    this.routes = routes

    // Setup restify routes
    for (let index = 0; index < this.routes.length; index++) {
      const route = this.routes[index]
      console.log(`Router => Setting up route ${route.path}`)

      route.action(this.server, route)
      // this.server.app[route.method]
    }
  }
}
