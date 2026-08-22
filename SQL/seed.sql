-- Seeds one real account and two domains, matching what's already
-- being tested manually. Run this once in the SQL Editor.

insert into accounts (email, plan)
values ('zonaazulcrconsulting@gmail.com', 'free');

insert into domains (account_id, hostname)
select id, 'revelrybeverages.com' from accounts where email = 'zonaazulcrconsulting@gmail.com'
union all
select id, 'revelrysupply.com' from accounts where email = 'zonaazulcrconsulting@gmail.com';
