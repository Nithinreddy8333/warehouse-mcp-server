-- One row per customer with contact details and lifetime order metrics.
with orders as (
    select
        customer_id,
        count(*)                                                as order_count,
        sum(amount) filter (where not is_cancelled_or_returned) as lifetime_value,
        max(order_date)                                         as last_order_date
    from marts.fct_orders
    group by 1
)
select
    c.customer_id,
    c.full_name,
    c.email,
    c.phone,
    c.country,
    c.signup_date,
    coalesce(o.order_count, 0)    as order_count,
    coalesce(o.lifetime_value, 0) as lifetime_value,
    o.last_order_date
from staging.stg_customers c
left join orders o using (customer_id)
