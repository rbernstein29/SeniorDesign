FROM ruby:3.3.8-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential \
      libpq-dev \
      postgresql-client \
      curl \
      git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Gems layer cached separately — only rebuilds when Gemfile changes
COPY Gemfile Gemfile.lock ./
RUN bundle install --jobs 4 --retry 3

COPY . .

EXPOSE 3000

ENTRYPOINT ["docker/entrypoint.sh"]
CMD ["bundle", "exec", "rails", "server", "-p", "3000", "-b", "0.0.0.0"]
