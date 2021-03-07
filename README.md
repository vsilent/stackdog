[![Crates.io](https://img.shields.io/crates/v/stackdog.svg)](https://crates.io/crates/stackdog)
[![Docs.rs](https://docs.rs/stackdog/badge.svg)](https://docs.rs/stackdog)
[![Coverage Status](https://coveralls.io/repos/github/vsilent/stackdog/badge.svg?branch=master)](https://coveralls.io/github/vsilent/stackdog?branch=master)
[![Build Status](https://travis-ci.com/vsilent/stackdog.svg?branch=master)](https://travis-ci.com/trydirect/stackdog)
![Docker Stars](https://img.shields.io/docker/stars/trydirect/stackdog.svg)
![Docker Pulls](https://img.shields.io/docker/pulls/trydirect/stackdog.svg)
[![Gitter chat](https://badges.gitter.im/stackdog/community.png)](https://gitter.im/stackdog/community)


<p></p><p></p><p></p>

<p align="center">
<img src="https://user-images.githubusercontent.com/42473/109795596-c7a14f00-7c1f-11eb-8358-583d4008f42d.jpg">
</p>


**Server management tool written in Rust for fast and secure management of containerized applications**



## Table of contents
- [Quick start](#quick-start)
- [Request a feature](https://github.com/vsilent/stackdog/issues/new) 
- [Documentation](#documentation)
- [Contributing](#contributing)
- [Community](#community)
- [Versioning](#versioning)
- [Creators](#creators)
- [License](#license)


### Quick start

This project is at early stage of development, see development [ROADMAP.md](ROADMAP.md)

### Setup development environment

```
cp .env.sample .env
docker-compose up
```

### Documentation
Stackdogs's documentation, included into this repo, is built with Jekyll and 
publicly hosted on GitHub Pages at https://stackdog.io 

### Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).


### Versioning
Stackdog is maintained under the [the Semantic Versioning guidelines](https://semver.org/).

## Community

Get updates on Bootstrap's development and chat with the project maintainers and community members.

- Follow [@stackdog1 on Twitter](https://twitter.com/stackdog1).
- Join [the official Gitter room](https://gitter.im/stackdog/community).

### Creators
**Vasili Pascal**
- <https://twitter.com/VasiliiPascal>
- <https://github.com/vsilent>


### Sponsors

Support this project by becoming a sponsor. Your logo will show up in this README with a link to your website. 

[Become a sponsor!](https://opencollective.com/stackdog#sponsor)


### Contributors
This project exists thanks to all the people who contribute.

### Backers

Thank you to all our backers! 🙏 [Become a backer](https://opencollective.com/stackdog#backer)

<a href="https://opencollective.com/stackdog#backers" target="_blank"><img src="https://opencollective.com/stackdog/backers.svg?width=890" /></a>


### Inspired by 

- [Portainer](https://github.com/portainer/portainer) - A lightweight management UI for managing your Docker hosts or Docker Swarm clusters by [@portainer](https://github.com/portainer)
- [Seagull](https://github.com/tobegit3hub/seagull) - Friendly Web UI to monitor docker daemon. by [@tobegit3hub](https://github.com/tobegit3hub)
- [Swarmpit](https://github.com/swarmpit/swarmpit) - Swarmpit provides simple and easy to use interface for your Docker Swarm cluster. You can manage your stacks, services, secrets, volumes, networks etc.
- [Swirl](https://github.com/cuigh/swirl) - Swirl is a web management tool for Docker, focused on swarm cluster By [@cuigh](https://github.com/cuigh/)
- [Yacht](https://github.com/SelfhostedPro/Yacht) :construction: - A Web UI for docker that focuses on templates and ease of use in order to make deployments as easy as possible. By [@SelfhostedPro](https://github.com/SelfhostedPro)

### Why another container management tool ?
- Written in Rust 
- Better security 
- Better performance
- Modular design

## License
[MIT](LICENSE-MIT)