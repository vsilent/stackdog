# JSON constructor

## Developer usage

We use Webpack dev server with hot reload, so you can serve it locally and see all changes immediately.

`npm install`
`npm run start`

OR

`docker build -t stackdog -f Dockerfile .`
`docker run stackdog`

## Production build

`npm install`
`npm run build`

## Development notes

# 1
Never, ever, ever don't spend time on experimental react branch integration with TypeScript support.  
They unstable, and... just don't work endeed.  