declare module 'express' {
  function express(): {
    use(handler: any): void;
    get(path: string, handler: express.RequestHandler): void;
    post(path: string, handler: express.RequestHandler): void;
    put(path: string, handler: express.RequestHandler): void;
    delete(path: string, handler: express.RequestHandler): void;
    listen(port: number | string, callback?: () => void): void;
  };
  namespace express {
    interface Request {
      body: any;
      query: Record<string, any>;
      params: Record<string, string>;
    }
    interface Response {
      json(body: any): Response;
      status(code: number): Response;
    }
    type RequestHandler = (req: Request, res: Response) => any;
    function json(): any;
  }
  export = express;
}

declare module 'cors' {
  function cors(options?: any): any;
  export = cors;
}
