#include "capture.h"

t_list *lst_init(void *content)
{
	t_list *new;

	new = (t_list *)malloc(sizeof(t_list));
	new->content = content;
	new->next = NULL;
	return new;
}

t_list *lst_add_front(t_list **lst, void *content)
{
	t_list *new;

	if (!lst || !content)
		return NULL;
	if (*lst == NULL)
		return lst_init(content);
	new = lst_init(content);
	new->next = *lst;
	*lst = new;
	return new;
}

t_list *lst_add_rear(t_list **lst, void *content)
{
	t_list *new;

	if (!lst || !content)
		return NULL;
	if (*lst == NULL)
		return lst_init(content);
	new = lst_init(content);
	while ((*lst) && (*lst)->next)
		lst = &(*lst)->next;
	*lst = new;
	return *lst;
}

void lst_clear(t_list **lst)
{
	t_list *current;
	t_list *next;

	if (!lst)
		return;
	current = *lst;
	while (current)
	{
		next = current->next;
		free(current->content);
		free(current);
		current = next;
	}
	*lst = NULL;
}
