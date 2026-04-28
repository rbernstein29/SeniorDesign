FROM ruby:3.3-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential \
      libpq-dev \
      postgresql-client \
      libxml2-dev \
      libxslt1-dev \
      libyaml-dev \
      zlib1g-dev \
      curl \
      git \
      iputils-ping \
      iproute2 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

ENV BUNDLE_PATH=/usr/local/bundle \
    BUNDLE_JOBS=4 \
    BUNDLE_RETRY=3

# Gems layer cached separately — only rebuilds when Gemfile changes
COPY Gemfile Gemfile.lock ./
RUN bundle install

COPY . .

EXPOSE 3000

ENTRYPOINT ["docker/entrypoint.sh"]
CMD ["bundle", "exec", "rails", "server", "-p", "3000", "-b", "0.0.0.0"]
