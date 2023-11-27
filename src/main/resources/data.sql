--USERS
INSERT INTO users (id, email, first_name, last_name, password, created_at, provider)
VALUES
    ('ba804cb9-fa14-42a5-afaf-be488742fc54', 'admin@example.com', 'James', 'Bond', '$2a$10$TM3PAYG3b.H98cbRrHqWa.BM7YyCqV92e/kUTBfj85AjayxGZU7d6', NOW(), "LOCAL"), -- Password: 1234
    ('0d8fa44c-54fd-4cd0-ace9-2a7da57992de', 'user@example.com', 'Tyler', 'Durden', '$2a$10$TM3PAYG3b.H98cbRrHqWa.BM7YyCqV92e/kUTBfj85AjayxGZU7d6', NOW(), "LOCAL") -- Password: 1234
ON CONFLICT DO NOTHING;

--ROLES
INSERT INTO role(id, name)
VALUES
    ('ab505c92-7280-49fd-a7de-258e618df074', 'ADMIN'),
    ('c6aee32d-8c35-4481-8b3e-a876a39b0c02', 'USER')
ON CONFLICT DO NOTHING;

--AUTHORITIES
INSERT INTO authority(id, name)
VALUES
    ('76d2cbf6-5845-470e-ad5f-2edb9e09a868', 'USER_MODIFY'),
    ('21c942db-a275-43f8-bdd6-d048c21bf5ab', 'USER_DELETE'),
    ('0d33ea98-2be6-429c-a2c3-9421451c39a6', 'USER_READ'),
    ('7e5835ea-6af3-40e5-8552-5a5f89054b3c', 'USER_READ_ALL')
ON CONFLICT DO NOTHING;

--assign roles to users
insert into users_role (users_id, role_id)
values
    ('ba804cb9-fa14-42a5-afaf-be488742fc54', 'ab505c92-7280-49fd-a7de-258e618df074'),
    ('ba804cb9-fa14-42a5-afaf-be488742fc54', 'c6aee32d-8c35-4481-8b3e-a876a39b0c02'),
    ('0d8fa44c-54fd-4cd0-ace9-2a7da57992de', 'c6aee32d-8c35-4481-8b3e-a876a39b0c02')
ON CONFLICT DO NOTHING;

--assign authorities to roles
INSERT INTO role_authority(role_id, authority_id)
VALUES
    ('ab505c92-7280-49fd-a7de-258e618df074', '21c942db-a275-43f8-bdd6-d048c21bf5ab'),
    ('ab505c92-7280-49fd-a7de-258e618df074','7e5835ea-6af3-40e5-8552-5a5f89054b3c'),
    ('c6aee32d-8c35-4481-8b3e-a876a39b0c02', '76d2cbf6-5845-470e-ad5f-2edb9e09a868'),
    ('c6aee32d-8c35-4481-8b3e-a876a39b0c02', '0d33ea98-2be6-429c-a2c3-9421451c39a6')
ON CONFLICT DO NOTHING;