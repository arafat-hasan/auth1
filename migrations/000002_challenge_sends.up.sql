-- The sends of each challenge, one row per send, for the send limits per value (TDD-07 §5, L-7).
-- challenges.sends and last_sent_at hold only how many sends a challenge had and when the last
-- one was, so a count over them cannot tell which sends fell within a window: a challenge that
-- lives 24 h would count all its sends whenever one of them was recent. target_bidx is the
-- challenge's, copied so that the limit query reads one index. Rows are deleted with their
-- challenge (TDD-01 §5).
CREATE TABLE challenge_sends (
    challenge_id uuid NOT NULL REFERENCES challenges (id),
    send         integer NOT NULL CHECK (send > 0),            -- challenges.sends after this send
    target_bidx  bytea NOT NULL,
    sent_at      timestamptz NOT NULL,
    PRIMARY KEY (challenge_id, send)
);
CREATE INDEX challenge_sends_target ON challenge_sends (target_bidx, sent_at);  -- send limits per value

GRANT SELECT, INSERT, UPDATE, DELETE ON challenge_sends TO auth1_app;
