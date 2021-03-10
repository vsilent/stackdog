# JSON constructor

## Developer usage

We use Webpack dev server with hot reload, so you can serve it locally and see all changes immediately.

`cd ./web`
`npm install`
`npm run start`

OR

`cd ./web`
`docker build . -t stackdog`
`docker run -p8080:8080 stackdog`

## Production build

`npm install`
`npm run build`

## Development notes

# 1
Never, ever, ever don't spend time on experimental react branch integration with TypeScript support.  
They unstable, and... just don't work endeed.  
