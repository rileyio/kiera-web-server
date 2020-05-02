import { Server } from '..'

export interface Route {
  action: (server: Server, route: Route) => void
  method: 'get' | 'post'
  middleware: Array<any>
  path: string
  view: string
}
