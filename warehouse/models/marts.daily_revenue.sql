-- Revenue per day and product category, excluding cancelled and returned orders.
select
    order_date,
    category,
    count(*)    as orders,
    sum(amount) as revenue
from marts.fct_orders
where not is_cancelled_or_returned
group by 1, 2
