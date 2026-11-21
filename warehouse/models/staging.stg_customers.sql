-- Customers with tidy text fields. One row per customer.
select
    customer_id,
    trim(full_name)        as full_name,
    lower(trim(email))     as email,
    phone,
    upper(country)         as country,
    signup_date
from raw.customers
